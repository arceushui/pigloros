//! Provider-neutral framing for the non-execute Sandbox Provider operations.

use ciborium::value::Value;

use super::codec::{
    array, bounded_text, decode, digest, encode, fixed, sign, text, uint, validate_magic,
    value_bytes, value_text, value_uint, verify,
};
use super::protocol::{
    decode_request_authority, request_authority_value, validate_request_authority,
    RequestAuthorityV1,
};
use super::{
    SandboxContractErrorV1, MAX_SANDBOX_IDENTIFIER_BYTES_V1, MAX_SANDBOX_SAFE_DETAIL_BYTES_V1,
};

const SDQ1: &str = "SDQ1";
const SDY1: &str = "SDY1";
const SCQ1: &str = "SCQ1";
const SCY1: &str = "SCY1";
const SRQ1: &str = "SRQ1";
const SRY1: &str = "SRY1";
const SLE1: &str = "SLE1";

/// Closed Sandbox Provider operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProviderOperationV1 {
    /// Report provider identity and active authority.
    Describe,
    /// Admit and execute one attempt.
    Execute,
    /// Cancel one admitted attempt.
    Cancel,
    /// Prove that one attempt has no residual resources.
    Reconcile,
}

impl SandboxProviderOperationV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Describe => 0,
            Self::Execute => 1,
            Self::Cancel => 2,
            Self::Reconcile => 3,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::Describe),
            1 => Ok(Self::Execute),
            2 => Ok(Self::Cancel),
            3 => Ok(Self::Reconcile),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }
}

/// Exact self-digested SDQ1 describe request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescribeRequestV1 {
    /// Request identity and active policy authority.
    pub authority: RequestAuthorityV1,
    /// Self-digest of the exact SDQ1-U array.
    pub request_digest: [u8; 32],
}

/// Exact runtime-key-signed SDY1 describe response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescribeResponseV1 {
    /// Identity of the SDQ1 request being answered.
    pub request_id: [u8; 16],
    /// Exact selected SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact running provider-binary digest.
    pub provider_binary_digest: [u8; 32],
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// Exact active APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SDY1-U array.
    pub response_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Exact self-digested SCQ1 cancel request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCancelRequestV1 {
    /// Request identity and active policy authority.
    pub authority: RequestAuthorityV1,
    /// Exact nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Exact admission-grant digest for the attempt.
    pub agr1_digest: [u8; 32],
    /// Self-digest of the exact SCQ1-U array.
    pub request_digest: [u8; 32],
}

/// Closed SCY1 cancellation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxCancelResultV1 {
    /// The attempt was already terminal and was not changed.
    AlreadyTerminal,
    /// This request cancelled the attempt and completed cleanup.
    CancelledAndCleaned,
}

impl SandboxCancelResultV1 {
    const fn code(self) -> u64 {
        match self {
            Self::AlreadyTerminal => 0,
            Self::CancelledAndCleaned => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::AlreadyTerminal),
            1 => Ok(Self::CancelledAndCleaned),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }
}

/// Exact runtime-key-signed SCY1 cancel response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCancelResponseV1 {
    /// Identity of the SCQ1 request being answered.
    pub request_id: [u8; 16],
    /// Exact attempt identity from SCQ1.
    pub attempt_id: [u8; 16],
    /// Closed idempotent cancellation result.
    pub result: SandboxCancelResultV1,
    /// Exact terminal SPY1 digest.
    pub spy1_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SCY1-U array.
    pub response_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Exact self-digested SRQ1 reconciliation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReconcileRequestV1 {
    /// Request identity and active policy authority.
    pub authority: RequestAuthorityV1,
    /// Exact nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Exact admission-grant digest for the attempt.
    pub agr1_digest: [u8; 32],
    /// Self-digest of the exact SRQ1-U array.
    pub request_digest: [u8; 32],
}

/// Exact runtime-key-signed SRY1 clean reconciliation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReconcileResponseV1 {
    /// Identity of the SRQ1 request being answered.
    pub request_id: [u8; 16],
    /// Exact attempt identity from SRQ1.
    pub attempt_id: [u8; 16],
    /// Literal true; residual resources must instead produce signed SPE1.
    pub clean: bool,
    /// Exact reconciliation-evidence digest.
    pub reconciliation_evidence_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SRY1-U array.
    pub response_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Closed unsigned local selector failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxLocalErrorCodeV1 {
    /// No selected provider could be reached.
    ProviderUnavailable,
    /// The selected provider identity was invalid.
    ProviderIdentityInvalid,
    /// Active policy could not be loaded or validated.
    PolicyUnavailable,
    /// The authenticated control channel could not be established.
    ControlChannelUnavailable,
    /// The selector request was malformed or incomplete.
    InvalidSelectorRequest,
    /// Evaluator-supplied authority differed from immutable authority.
    RequestAuthorityMismatch,
    /// A selector control or payload limit was exceeded.
    PayloadLimitExceeded,
    /// Recovery failed to obtain authenticated terminal evidence.
    ProviderTerminalUnavailable,
    /// Provider evidence was malformed, substituted, or incomplete.
    ProviderEvidenceInvalid,
}

impl SandboxLocalErrorCodeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::ProviderUnavailable => 0,
            Self::ProviderIdentityInvalid => 1,
            Self::PolicyUnavailable => 2,
            Self::ControlChannelUnavailable => 3,
            Self::InvalidSelectorRequest => 4,
            Self::RequestAuthorityMismatch => 5,
            Self::PayloadLimitExceeded => 6,
            Self::ProviderTerminalUnavailable => 7,
            Self::ProviderEvidenceInvalid => 8,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::ProviderUnavailable),
            1 => Ok(Self::ProviderIdentityInvalid),
            2 => Ok(Self::PolicyUnavailable),
            3 => Ok(Self::ControlChannelUnavailable),
            4 => Ok(Self::InvalidSelectorRequest),
            5 => Ok(Self::RequestAuthorityMismatch),
            6 => Ok(Self::PayloadLimitExceeded),
            7 => Ok(Self::ProviderTerminalUnavailable),
            8 => Ok(Self::ProviderEvidenceInvalid),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }
}

/// Closed point in selector processing at which a local failure occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxLocalErrorPhaseV1 {
    /// SLX1/SPX1 construction or authority validation was not complete.
    BeforeSpx1,
    /// SPX1 was complete but AGR1 had not been authenticated.
    AfterSpx1BeforeAdmission,
    /// AGR1 had been authenticated.
    AfterAdmission,
}

impl SandboxLocalErrorPhaseV1 {
    const fn code(self) -> u64 {
        match self {
            Self::BeforeSpx1 => 0,
            Self::AfterSpx1BeforeAdmission => 1,
            Self::AfterAdmission => 2,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::BeforeSpx1),
            1 => Ok(Self::AfterSpx1BeforeAdmission),
            2 => Ok(Self::AfterAdmission),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }
}

/// Exact bounded unsigned SLE1 local selector evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxLocalErrorV1 {
    /// Point in selector processing at which the failure occurred.
    pub phase: SandboxLocalErrorPhaseV1,
    /// Operation, absent only when framing prevents its identification.
    pub operation: Option<SandboxProviderOperationV1>,
    /// Request identity, absent only when no complete canonical nonzero ID was decoded.
    pub request_id: Option<[u8; 16]>,
    /// Attempt identity, present exactly after complete SPX1 construction.
    pub attempt_id: Option<[u8; 16]>,
    /// Authenticated AGR1 digest, present exactly after admission.
    pub agr1_digest: Option<[u8; 32]>,
    /// Closed local failure code.
    pub code: SandboxLocalErrorCodeV1,
    /// Optional nonempty bounded diagnostic safe to disclose.
    pub safe_detail: Option<String>,
}

fn validate_signature(signature: &[u8; 64]) -> Result<(), SandboxContractErrorV1> {
    (signature != &[0; 64])
        .then_some(())
        .ok_or(SandboxContractErrorV1::SignatureInvalid)
}

fn encode_request(
    unsigned: Value,
    request_digest: &[u8; 32],
) -> Result<Vec<u8>, SandboxContractErrorV1> {
    encode(&Value::Array(vec![unsigned, value_bytes(request_digest)]))
}

fn encode_response(
    unsigned: Value,
    response_digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<Vec<u8>, SandboxContractErrorV1> {
    encode(&Value::Array(vec![
        unsigned,
        value_bytes(response_digest),
        value_bytes(signature),
    ]))
}

macro_rules! impl_attempt_request {
    ($type:ty, $magic:ident) => {
        impl $type {
            /// Compute and install the exact request self-digest.
            ///
            /// # Errors
            /// Returns a closed contract error when an unsigned field is invalid.
            pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
                self.validate_unsigned()?;
                self.request_digest = digest($magic, &self.unsigned_value())?;
                Ok(self)
            }

            /// Validate authority, exact attempt identity, and the self-digest.
            ///
            /// # Errors
            /// Returns a closed contract error for invalid request data.
            pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
                self.validate_unsigned()?;
                if self.request_digest == [0; 32] {
                    return Err(SandboxContractErrorV1::FieldOutOfBounds);
                }
                (self.request_digest == digest($magic, &self.unsigned_value())?)
                    .then_some(())
                    .ok_or(SandboxContractErrorV1::DigestMismatch)
            }

            /// Encode the exact deterministic-CBOR request.
            ///
            /// # Errors
            /// Returns a closed contract error for invalid request data.
            pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
                self.validate()?;
                encode_request(self.unsigned_value(), &self.request_digest)
            }

            fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
                validate_request_authority(&self.authority)?;
                if self.attempt_id == [0; 16] || self.agr1_digest == [0; 32] {
                    Err(SandboxContractErrorV1::FieldOutOfBounds)
                } else {
                    Ok(())
                }
            }

            fn unsigned_value(&self) -> Value {
                Value::Array(vec![
                    value_text($magic),
                    value_uint(1),
                    request_authority_value(&self.authority),
                    value_bytes(&self.attempt_id),
                    value_bytes(&self.agr1_digest),
                ])
            }
        }
    };
}

impl_attempt_request!(SandboxCancelRequestV1, SCQ1);
impl_attempt_request!(SandboxReconcileRequestV1, SRQ1);

impl SandboxDescribeRequestV1 {
    /// Compute and install the exact SDQ1 request self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error when authority is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        validate_request_authority(&self.authority)?;
        self.request_digest = digest(SDQ1, &self.unsigned_value())?;
        Ok(self)
    }

    /// Validate authority and the exact SDQ1 self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid request data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        validate_request_authority(&self.authority)?;
        if self.request_digest == [0; 32] {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        (self.request_digest == digest(SDQ1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Encode exact deterministic-CBOR SDQ1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid request data.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_request(self.unsigned_value(), &self.request_digest)
    }

    /// Decode exact deterministic-CBOR SDQ1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<2>(&value)?;
        let unsigned = array::<3>(&fields[0])?;
        validate_magic(unsigned, SDQ1)?;
        let request = Self {
            authority: decode_request_authority(&unsigned[2])?,
            request_digest: fixed(&fields[1])?,
        };
        request.validate().map(|()| request)
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SDQ1),
            value_uint(1),
            request_authority_value(&self.authority),
        ])
    }
}

impl SandboxCancelRequestV1 {
    /// Decode exact deterministic-CBOR SCQ1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let (authority, attempt_id, agr1_digest, request_digest) =
            decode_attempt_request(bytes, SCQ1)?;
        let request = Self {
            authority,
            attempt_id,
            agr1_digest,
            request_digest,
        };
        request.validate().map(|()| request)
    }
}

impl SandboxReconcileRequestV1 {
    /// Decode exact deterministic-CBOR SRQ1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let (authority, attempt_id, agr1_digest, request_digest) =
            decode_attempt_request(bytes, SRQ1)?;
        let request = Self {
            authority,
            attempt_id,
            agr1_digest,
            request_digest,
        };
        request.validate().map(|()| request)
    }
}

type AttemptRequestFieldsV1 = (RequestAuthorityV1, [u8; 16], [u8; 32], [u8; 32]);

fn decode_attempt_request(
    bytes: &[u8],
    magic: &str,
) -> Result<AttemptRequestFieldsV1, SandboxContractErrorV1> {
    let value = decode(bytes)?;
    let fields = array::<2>(&value)?;
    let unsigned = array::<5>(&fields[0])?;
    validate_magic(unsigned, magic)?;
    Ok((
        decode_request_authority(&unsigned[2])?,
        fixed(&unsigned[3])?,
        fixed(&unsigned[4])?,
        fixed(&fields[1])?,
    ))
}

macro_rules! impl_signed_response {
    (
        $type:ty,
        $magic:ident,
        $unsigned_length:literal,
        |$unsigned_fields:ident, $wrapper_fields:ident| $decode:block
    ) => {
        impl $type {
            /// Seal and sign this response with the runtime-attestation key.
            ///
            /// # Errors
            /// Returns a closed contract error when an unsigned field is invalid.
            pub fn sign(
                mut self,
                key: &ed25519_dalek::SigningKey,
            ) -> Result<Self, SandboxContractErrorV1> {
                self.validate_unsigned()?;
                self.response_digest = digest($magic, &self.unsigned_value())?;
                self.signature = sign($magic, &self.response_digest, key);
                Ok(self)
            }

            /// Validate bounds, identities, signature shape, and self-digest.
            ///
            /// # Errors
            /// Returns a closed contract error for invalid response data.
            pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
                self.validate_unsigned()?;
                if self.response_digest == [0; 32] {
                    return Err(SandboxContractErrorV1::FieldOutOfBounds);
                }
                validate_signature(&self.signature)?;
                (self.response_digest == digest($magic, &self.unsigned_value())?)
                    .then_some(())
                    .ok_or(SandboxContractErrorV1::DigestMismatch)
            }

            /// Verify the response with an authorized runtime-attestation key.
            ///
            /// # Errors
            /// Returns a closed contract error for invalid data or signature.
            pub fn verify_signature(
                &self,
                key: &ed25519_dalek::VerifyingKey,
            ) -> Result<(), SandboxContractErrorV1> {
                self.validate()?;
                verify($magic, &self.response_digest, &self.signature, key)
            }

            /// Encode the exact deterministic-CBOR signed response.
            ///
            /// # Errors
            /// Returns a closed contract error for invalid response data.
            pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
                self.validate()?;
                encode_response(
                    self.unsigned_value(),
                    &self.response_digest,
                    &self.signature,
                )
            }

            /// Decode exact deterministic-CBOR signed response bytes.
            ///
            /// # Errors
            /// Returns a closed contract error for malformed or noncanonical input.
            pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
                let value = decode(bytes)?;
                let $wrapper_fields = array::<3>(&value)?;
                let $unsigned_fields = array::<$unsigned_length>(&$wrapper_fields[0])?;
                validate_magic($unsigned_fields, $magic)?;
                let response: Self = $decode;
                response.validate().map(|()| response)
            }
        }
    };
}

impl_signed_response!(SandboxDescribeResponseV1, SDY1, 8, |unsigned, fields| {
    SandboxDescribeResponseV1 {
        request_id: fixed(&unsigned[2])?,
        spm1_digest: fixed(&unsigned[3])?,
        provider_binary_digest: fixed(&unsigned[4])?,
        hcp1_digest: fixed(&unsigned[5])?,
        apt1_digest: fixed(&unsigned[6])?,
        runtime_attestation_key_id: text(&unsigned[7])?.to_owned(),
        response_digest: fixed(&fields[1])?,
        signature: fixed(&fields[2])?,
    }
});

impl_signed_response!(SandboxCancelResponseV1, SCY1, 7, |unsigned, fields| {
    SandboxCancelResponseV1 {
        request_id: fixed(&unsigned[2])?,
        attempt_id: fixed(&unsigned[3])?,
        result: SandboxCancelResultV1::from_code(uint(&unsigned[4])?)?,
        spy1_digest: fixed(&unsigned[5])?,
        runtime_attestation_key_id: text(&unsigned[6])?.to_owned(),
        response_digest: fixed(&fields[1])?,
        signature: fixed(&fields[2])?,
    }
});

impl_signed_response!(SandboxReconcileResponseV1, SRY1, 7, |unsigned, fields| {
    SandboxReconcileResponseV1 {
        request_id: fixed(&unsigned[2])?,
        attempt_id: fixed(&unsigned[3])?,
        clean: decode_literal_true(&unsigned[4])?,
        reconciliation_evidence_digest: fixed(&unsigned[5])?,
        runtime_attestation_key_id: text(&unsigned[6])?.to_owned(),
        response_digest: fixed(&fields[1])?,
        signature: fixed(&fields[2])?,
    }
});

impl SandboxDescribeResponseV1 {
    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        validate_response_fields(
            self.request_id,
            &[
                self.spm1_digest,
                self.provider_binary_digest,
                self.hcp1_digest,
                self.apt1_digest,
            ],
            &self.runtime_attestation_key_id,
        )
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SDY1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.spm1_digest),
            value_bytes(&self.provider_binary_digest),
            value_bytes(&self.hcp1_digest),
            value_bytes(&self.apt1_digest),
            value_text(&self.runtime_attestation_key_id),
        ])
    }

    /// Validate that this response answers the exact request and active APT1.
    ///
    /// # Errors
    /// Returns an identity error when the request ID or APT1 digest differs.
    pub fn validate_for_request(
        &self,
        request: &SandboxDescribeRequestV1,
    ) -> Result<(), SandboxContractErrorV1> {
        request.validate()?;
        self.validate()?;
        if self.request_id == request.authority.request_id
            && self.apt1_digest == request.authority.apt1_digest
        {
            Ok(())
        } else {
            Err(SandboxContractErrorV1::InconsistentFields)
        }
    }
}

impl SandboxCancelResponseV1 {
    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        validate_response_fields(
            self.request_id,
            &[self.spy1_digest],
            &self.runtime_attestation_key_id,
        )?;
        if self.attempt_id == [0; 16] {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SCY1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
            value_uint(self.result.code()),
            value_bytes(&self.spy1_digest),
            value_text(&self.runtime_attestation_key_id),
        ])
    }

    /// Validate the exact request and attempt identity answered by this response.
    ///
    /// # Errors
    /// Returns an identity error when request or attempt identity differs.
    pub fn validate_for_request(
        &self,
        request: &SandboxCancelRequestV1,
    ) -> Result<(), SandboxContractErrorV1> {
        request.validate()?;
        self.validate()?;
        validate_response_identity(
            self.request_id,
            self.attempt_id,
            &request.authority,
            request.attempt_id,
        )
    }
}

impl SandboxReconcileResponseV1 {
    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        validate_response_fields(
            self.request_id,
            &[self.reconciliation_evidence_digest],
            &self.runtime_attestation_key_id,
        )?;
        if self.attempt_id == [0; 16] || !self.clean {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SRY1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
            Value::Bool(self.clean),
            value_bytes(&self.reconciliation_evidence_digest),
            value_text(&self.runtime_attestation_key_id),
        ])
    }

    /// Validate the exact request and attempt identity answered by this response.
    ///
    /// # Errors
    /// Returns an identity error when request or attempt identity differs.
    pub fn validate_for_request(
        &self,
        request: &SandboxReconcileRequestV1,
    ) -> Result<(), SandboxContractErrorV1> {
        request.validate()?;
        self.validate()?;
        validate_response_identity(
            self.request_id,
            self.attempt_id,
            &request.authority,
            request.attempt_id,
        )
    }
}

fn validate_response_fields(
    request_id: [u8; 16],
    digests: &[[u8; 32]],
    key_id: &str,
) -> Result<(), SandboxContractErrorV1> {
    if request_id == [0; 16]
        || digests.contains(&[0; 32])
        || !bounded_text(key_id, MAX_SANDBOX_IDENTIFIER_BYTES_V1)
    {
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_response_identity(
    response_request_id: [u8; 16],
    response_attempt_id: [u8; 16],
    request_authority: &RequestAuthorityV1,
    request_attempt_id: [u8; 16],
) -> Result<(), SandboxContractErrorV1> {
    if response_request_id == request_authority.request_id
        && response_attempt_id == request_attempt_id
    {
        Ok(())
    } else {
        Err(SandboxContractErrorV1::InconsistentFields)
    }
}

fn decode_literal_true(value: &Value) -> Result<bool, SandboxContractErrorV1> {
    if value == &Value::Bool(true) {
        Ok(true)
    } else {
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    }
}

impl SandboxLocalErrorV1 {
    /// Validate and encode exact deterministic-CBOR SLE1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid local evidence.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            value_text(SLE1),
            value_uint(1),
            value_uint(self.phase.code()),
            self.operation
                .map_or(Value::Null, |operation| value_uint(operation.code())),
            self.request_id
                .as_ref()
                .map_or(Value::Null, |request_id| value_bytes(request_id)),
            self.attempt_id
                .as_ref()
                .map_or(Value::Null, |attempt_id| value_bytes(attempt_id)),
            self.agr1_digest
                .as_ref()
                .map_or(Value::Null, |digest| value_bytes(digest)),
            value_uint(self.code.code()),
            self.safe_detail
                .as_ref()
                .map_or(Value::Null, |detail| value_text(detail)),
        ]))
    }

    /// Decode exact deterministic-CBOR SLE1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<9>(&value)?;
        validate_magic(fields, SLE1)?;
        let error = Self {
            phase: SandboxLocalErrorPhaseV1::from_code(uint(&fields[2])?)?,
            operation: decode_optional_operation(&fields[3])?,
            request_id: decode_optional_request_id(&fields[4])?,
            attempt_id: decode_optional_request_id(&fields[5])?,
            agr1_digest: decode_optional_digest(&fields[6])?,
            code: SandboxLocalErrorCodeV1::from_code(uint(&fields[7])?)?,
            safe_detail: decode_optional_detail(&fields[8])?,
        };
        error.validate().map(|()| error)
    }

    /// Validate closed values and bounded disclosed detail.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid local evidence.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        let execute = self.operation == Some(SandboxProviderOperationV1::Execute);
        let request = self.request_id.is_some_and(|id| id != [0; 16]);
        let attempt = self.attempt_id.is_some_and(|id| id != [0; 16]);
        let admission = self.agr1_digest.is_some_and(|digest| digest != [0; 32]);
        let valid_shape = match self.phase {
            SandboxLocalErrorPhaseV1::BeforeSpx1 => {
                !admission
                    && matches!(
                        self.code,
                        SandboxLocalErrorCodeV1::PolicyUnavailable
                            | SandboxLocalErrorCodeV1::InvalidSelectorRequest
                            | SandboxLocalErrorCodeV1::RequestAuthorityMismatch
                            | SandboxLocalErrorCodeV1::PayloadLimitExceeded
                    )
                    && if matches!(
                        self.code,
                        SandboxLocalErrorCodeV1::RequestAuthorityMismatch
                            | SandboxLocalErrorCodeV1::PayloadLimitExceeded
                    ) {
                        execute && request && attempt
                    } else {
                        (!request && !attempt) || (request && execute)
                    }
            }
            SandboxLocalErrorPhaseV1::AfterSpx1BeforeAdmission => {
                execute
                    && request
                    && attempt
                    && !admission
                    && matches!(
                        self.code,
                        SandboxLocalErrorCodeV1::ProviderUnavailable
                            | SandboxLocalErrorCodeV1::ProviderIdentityInvalid
                            | SandboxLocalErrorCodeV1::ControlChannelUnavailable
                            | SandboxLocalErrorCodeV1::ProviderEvidenceInvalid
                    )
            }
            SandboxLocalErrorPhaseV1::AfterAdmission => {
                execute
                    && request
                    && attempt
                    && admission
                    && matches!(
                        self.code,
                        SandboxLocalErrorCodeV1::ControlChannelUnavailable
                            | SandboxLocalErrorCodeV1::ProviderTerminalUnavailable
                            | SandboxLocalErrorCodeV1::ProviderEvidenceInvalid
                    )
            }
        };
        if self.request_id == Some([0; 16])
            || self.attempt_id == Some([0; 16])
            || self.agr1_digest == Some([0; 32])
            || !valid_shape
            || self.safe_detail.as_ref().is_some_and(|detail| {
                detail.is_empty()
                    || detail.len() > MAX_SANDBOX_SAFE_DETAIL_BYTES_V1
                    || detail.contains('\0')
            })
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }
}

fn decode_optional_operation(
    value: &Value,
) -> Result<Option<SandboxProviderOperationV1>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        SandboxProviderOperationV1::from_code(uint(value)?).map(Some)
    }
}

fn decode_optional_request_id(value: &Value) -> Result<Option<[u8; 16]>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        fixed(value).map(Some)
    }
}

fn decode_optional_digest(value: &Value) -> Result<Option<[u8; 32]>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        fixed(value).map(Some)
    }
}

fn decode_optional_detail(value: &Value) -> Result<Option<String>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        text(value).map(|detail| Some(detail.to_owned()))
    }
}
