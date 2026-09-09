use ciborium::value::Value;

use super::codec::{
    array, bool_value, bytes_value, decode_document, digest32, encode, id16, key_id,
    optional_digest, optional_id16, optional_text, require_signature, self_digested, signed,
    text_value, uint, uint_value, valid_key_id, validate_magic, verify_digest, verify_signature,
    MAX_SAFE_DETAIL_BYTES,
};
use super::SandboxProviderProtocolError;

/// Closed Sandbox Provider operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProviderOperation {
    Describe,
    Execute,
    Cancel,
    Reconcile,
}

impl SandboxProviderOperation {
    const VALUES: [Self; 4] = [Self::Describe, Self::Execute, Self::Cancel, Self::Reconcile];

    fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        usize::try_from(code)
            .ok()
            .and_then(|index| Self::VALUES.get(index))
            .copied()
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    }

    const fn code(self) -> u64 {
        match self {
            Self::Describe => 0,
            Self::Execute => 1,
            Self::Cancel => 2,
            Self::Reconcile => 3,
        }
    }
}

/// Closed unsigned local selector failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxLocalErrorCode {
    ProviderUnavailable,
    ProviderIdentityInvalid,
    PolicyUnavailable,
    ControlChannelUnavailable,
    InvalidSelectorRequest,
    RequestAuthorityMismatch,
    PayloadLimitExceeded,
    ProviderTerminalUnavailable,
    ProviderEvidenceInvalid,
}

impl SandboxLocalErrorCode {
    const VALUES: [Self; 9] = [
        Self::ProviderUnavailable,
        Self::ProviderIdentityInvalid,
        Self::PolicyUnavailable,
        Self::ControlChannelUnavailable,
        Self::InvalidSelectorRequest,
        Self::RequestAuthorityMismatch,
        Self::PayloadLimitExceeded,
        Self::ProviderTerminalUnavailable,
        Self::ProviderEvidenceInvalid,
    ];

    fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        usize::try_from(code)
            .ok()
            .and_then(|index| Self::VALUES.get(index))
            .copied()
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    }

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
}

/// Closed point in selector processing at which a local failure occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxLocalErrorPhase {
    BeforeSpx1,
    AfterSpx1BeforeAdmission,
    AfterAdmission,
}

impl SandboxLocalErrorPhase {
    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::BeforeSpx1),
            1 => Ok(Self::AfterSpx1BeforeAdmission),
            2 => Ok(Self::AfterAdmission),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::BeforeSpx1 => 0,
            Self::AfterSpx1BeforeAdmission => 1,
            Self::AfterAdmission => 2,
        }
    }
}

/// Independently decoded unsigned SLE1 local selector evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxLocalError {
    pub phase: SandboxLocalErrorPhase,
    pub operation: Option<SandboxProviderOperation>,
    pub request_id: Option<[u8; 16]>,
    pub attempt_id: Option<[u8; 16]>,
    pub agr1_digest: Option<[u8; 32]>,
    pub code: SandboxLocalErrorCode,
    pub safe_detail: Option<String>,
}

impl SandboxLocalError {
    /// Decode and fully validate exact canonical SLE1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let fields = array::<9>(&value)?;
        validate_magic(fields, "SLE1")?;
        let error = decode_local_error(fields)?;
        validate_local_error_shape(&error)?;
        Ok(error)
    }

    /// Encode this validated selector-local failure in preferred deterministic CBOR.
    ///
    /// # Errors
    /// Returns a closed protocol error when the phase/code/nullability algebra is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        validate_local_error_shape(self)?;
        encode(&Value::Array(vec![
            text_value("SLE1"),
            uint_value(1),
            uint_value(self.phase.code()),
            self.operation
                .map_or(Value::Null, |operation| uint_value(operation.code())),
            self.request_id
                .as_ref()
                .map_or(Value::Null, |request_id| bytes_value(request_id)),
            self.attempt_id
                .as_ref()
                .map_or(Value::Null, |attempt_id| bytes_value(attempt_id)),
            self.agr1_digest
                .as_ref()
                .map_or(Value::Null, |digest| bytes_value(digest)),
            uint_value(self.code.code()),
            self.safe_detail
                .as_ref()
                .map_or(Value::Null, |detail| text_value(detail)),
        ]))
    }
}

fn decode_local_error(
    fields: &[Value; 9],
) -> Result<SandboxLocalError, SandboxProviderProtocolError> {
    Ok(SandboxLocalError {
        phase: SandboxLocalErrorPhase::decode(uint(&fields[2])?)?,
        operation: if fields[3] == Value::Null {
            None
        } else {
            Some(SandboxProviderOperation::decode(uint(&fields[3])?)?)
        },
        request_id: optional_id16(&fields[4])?,
        attempt_id: optional_id16(&fields[5])?,
        agr1_digest: optional_digest(&fields[6])?,
        code: SandboxLocalErrorCode::decode(uint(&fields[7])?)?,
        safe_detail: optional_text(&fields[8], MAX_SAFE_DETAIL_BYTES)?,
    })
}

fn validate_local_error_shape(
    error: &SandboxLocalError,
) -> Result<(), SandboxProviderProtocolError> {
    if error.request_id == Some([0; 16])
        || error.attempt_id == Some([0; 16])
        || error.agr1_digest == Some([0; 32])
    {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    let execute = error.operation == Some(SandboxProviderOperation::Execute);
    let request = error.request_id.is_some_and(|id| id != [0; 16]);
    let attempt = error.attempt_id.is_some_and(|id| id != [0; 16]);
    let admission = error.agr1_digest.is_some_and(|digest| digest != [0; 32]);
    let valid = match error.phase {
        SandboxLocalErrorPhase::BeforeSpx1 => {
            !admission
                && matches!(
                    error.code,
                    SandboxLocalErrorCode::PolicyUnavailable
                        | SandboxLocalErrorCode::InvalidSelectorRequest
                        | SandboxLocalErrorCode::RequestAuthorityMismatch
                        | SandboxLocalErrorCode::PayloadLimitExceeded
                )
                && if matches!(
                    error.code,
                    SandboxLocalErrorCode::RequestAuthorityMismatch
                        | SandboxLocalErrorCode::PayloadLimitExceeded
                ) {
                    execute && request && attempt
                } else {
                    (!request && !attempt) || (request && execute)
                }
        }
        SandboxLocalErrorPhase::AfterSpx1BeforeAdmission => {
            execute
                && request
                && attempt
                && !admission
                && matches!(
                    error.code,
                    SandboxLocalErrorCode::ProviderUnavailable
                        | SandboxLocalErrorCode::ProviderIdentityInvalid
                        | SandboxLocalErrorCode::ControlChannelUnavailable
                        | SandboxLocalErrorCode::ProviderEvidenceInvalid
                )
        }
        SandboxLocalErrorPhase::AfterAdmission => {
            execute
                && request
                && attempt
                && admission
                && matches!(
                    error.code,
                    SandboxLocalErrorCode::ControlChannelUnavailable
                        | SandboxLocalErrorCode::ProviderTerminalUnavailable
                        | SandboxLocalErrorCode::ProviderEvidenceInvalid
                )
        }
    };
    valid
        .then_some(())
        .ok_or(SandboxProviderProtocolError::InconsistentFields)
}

/// Authority common to every request operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAuthority {
    pub request_id: [u8; 16],
    pub apt1_digest: [u8; 32],
    pub policy_epoch: u64,
    pub nonce: [u8; 16],
}

pub(super) fn decode_request_authority(
    value: &Value,
) -> Result<RequestAuthority, SandboxProviderProtocolError> {
    let fields = array::<4>(value)?;
    Ok(RequestAuthority {
        request_id: id16(&fields[0])?,
        apt1_digest: digest32(&fields[1])?,
        policy_epoch: uint(&fields[2])?,
        nonce: id16(&fields[3])?,
    })
}

pub(super) fn validate_request_authority(
    value: &RequestAuthority,
) -> Result<(), SandboxProviderProtocolError> {
    if value.request_id == [0; 16] || value.apt1_digest == [0; 32] || value.nonce == [0; 16] {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

pub(super) fn request_authority_value(value: &RequestAuthority) -> Value {
    Value::Array(vec![
        bytes_value(&value.request_id),
        bytes_value(&value.apt1_digest),
        uint_value(value.policy_epoch),
        bytes_value(&value.nonce),
    ])
}

/// SDQ1 describe request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescribeRequest {
    pub request: RequestAuthority,
    pub request_digest: [u8; 32],
}

/// Signed SDY1 describe response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescribeResponse {
    pub request_id: [u8; 16],
    pub spm1_digest: [u8; 32],
    pub provider_binary_digest: [u8; 32],
    pub hcp1_digest: [u8; 32],
    pub active_apt1_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub response_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// SCQ1 cancel request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCancelRequest {
    pub request: RequestAuthority,
    pub attempt_id: [u8; 16],
    pub agr1_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

/// Closed SCY1 cancellation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxCancellationResult {
    AlreadyTerminal,
    CancelledAndCleaned,
}

/// Signed SCY1 cancel response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCancelResponse {
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub result: SandboxCancellationResult,
    pub terminal_spy1_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub response_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// SRQ1 reconcile request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReconcileRequest {
    pub request: RequestAuthority,
    pub attempt_id: [u8; 16],
    pub agr1_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

/// Signed successful SRY1 reconciliation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReconcileResponse {
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub clean: bool,
    pub reconciliation_evidence_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub response_digest: [u8; 32],
    pub signature: [u8; 64],
}

macro_rules! request_codec {
    ($type:ty, $magic:literal, $width:literal, $decode:expr_2021) => {
        impl $type {
            /// Decode and fully validate one exact canonical request record.
            ///
            /// # Errors
            /// Returns a closed protocol error for malformed or inconsistent input.
            pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
                let value = decode_document(bytes)?;
                let (fields, digest) = self_digested::<$width>(&value, $magic)?;
                let record: Self = ($decode)(fields, digest)?;
                validate_request_record(&record.request, $magic, fields, digest)?;
                Ok(record)
            }
        }
    };
}

request_codec!(
    SandboxDescribeRequest,
    "SDQ1",
    3,
    |fields: &[Value; 3], digest| Ok(Self {
        request: decode_request_authority(&fields[2])?,
        request_digest: digest,
    })
);

impl SandboxDescribeRequest {
    fn validate(&self) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = [
            text_value("SDQ1"),
            uint_value(1),
            request_authority_value(&self.request),
        ];
        validate_request_record(&self.request, "SDQ1", &unsigned, self.request_digest)
    }
}

impl SandboxCancelRequest {
    fn validate(&self) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = [
            text_value("SCQ1"),
            uint_value(1),
            request_authority_value(&self.request),
            bytes_value(&self.attempt_id),
            bytes_value(&self.agr1_digest),
        ];
        validate_attempt_binding(self.attempt_id, self.agr1_digest)?;
        validate_request_record(&self.request, "SCQ1", &unsigned, self.request_digest)
    }
}

impl SandboxReconcileRequest {
    fn validate(&self) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = [
            text_value("SRQ1"),
            uint_value(1),
            request_authority_value(&self.request),
            bytes_value(&self.attempt_id),
            bytes_value(&self.agr1_digest),
        ];
        validate_attempt_binding(self.attempt_id, self.agr1_digest)?;
        validate_request_record(&self.request, "SRQ1", &unsigned, self.request_digest)
    }
}

request_codec!(
    SandboxCancelRequest,
    "SCQ1",
    5,
    |fields: &[Value; 5], digest| {
        let record = Self {
            request: decode_request_authority(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            agr1_digest: digest32(&fields[4])?,
            request_digest: digest,
        };
        validate_attempt_binding(record.attempt_id, record.agr1_digest)?;
        Ok(record)
    }
);

request_codec!(
    SandboxReconcileRequest,
    "SRQ1",
    5,
    |fields: &[Value; 5], digest| {
        let record = Self {
            request: decode_request_authority(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            agr1_digest: digest32(&fields[4])?,
            request_digest: digest,
        };
        validate_attempt_binding(record.attempt_id, record.agr1_digest)?;
        Ok(record)
    }
);

macro_rules! signed_response_codec {
    ($type:ty, $magic:literal, $width:literal, $decode:expr_2021, $unsigned:expr_2021) => {
        impl $type {
            /// Decode and fully validate one exact canonical signed response.
            ///
            /// # Errors
            /// Returns a closed protocol error for malformed or inconsistent input.
            pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
                let value = decode_document(bytes)?;
                let (fields, digest, signature) = signed::<$width>(&value, $magic)?;
                let record: Self = ($decode)(fields, digest, signature)?;
                record.validate(fields)?;
                Ok(record)
            }

            /// Verify this response using a caller-authorized attestation key.
            ///
            /// # Errors
            /// Returns a closed protocol error when validation or verification fails.
            pub fn verify_signature(
                &self,
                key: &ed25519_dalek::VerifyingKey,
            ) -> Result<(), SandboxProviderProtocolError> {
                let unsigned = self.unsigned_value();
                self.validate(&unsigned)?;
                verify_signature($magic, &self.response_digest, &self.signature, key)
            }

            fn unsigned_value(&self) -> [Value; $width] {
                ($unsigned)(self)
            }
        }
    };
}

signed_response_codec!(
    SandboxDescribeResponse,
    "SDY1",
    8,
    |fields: &[Value; 8], digest, signature| Ok(Self {
        request_id: id16(&fields[2])?,
        spm1_digest: digest32(&fields[3])?,
        provider_binary_digest: digest32(&fields[4])?,
        hcp1_digest: digest32(&fields[5])?,
        active_apt1_digest: digest32(&fields[6])?,
        runtime_attestation_key_id: key_id(&fields[7])?,
        response_digest: digest,
        signature,
    }),
    |record: &SandboxDescribeResponse| [
        text_value("SDY1"),
        uint_value(1),
        bytes_value(&record.request_id),
        bytes_value(&record.spm1_digest),
        bytes_value(&record.provider_binary_digest),
        bytes_value(&record.hcp1_digest),
        bytes_value(&record.active_apt1_digest),
        text_value(&record.runtime_attestation_key_id),
    ]
);

impl SandboxDescribeResponse {
    fn validate(&self, unsigned: &[Value; 8]) -> Result<(), SandboxProviderProtocolError> {
        if self.request_id == [0; 16]
            || [
                self.spm1_digest,
                self.provider_binary_digest,
                self.hcp1_digest,
                self.active_apt1_digest,
            ]
            .contains(&[0; 32])
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        verify_digest("SDY1", unsigned, self.response_digest)
    }

    /// Validate that this response answers the exact request and active APT1.
    ///
    /// # Errors
    /// Returns a closed protocol error when either record is invalid or identities differ.
    pub fn validate_for_request(
        &self,
        request: &SandboxDescribeRequest,
    ) -> Result<(), SandboxProviderProtocolError> {
        request.validate()?;
        self.validate(&self.unsigned_value())?;
        if self.request_id == request.request.request_id
            && self.active_apt1_digest == request.request.apt1_digest
        {
            Ok(())
        } else {
            Err(SandboxProviderProtocolError::InconsistentFields)
        }
    }
}

signed_response_codec!(
    SandboxCancelResponse,
    "SCY1",
    7,
    |fields: &[Value; 7], digest, signature| Ok(Self {
        request_id: id16(&fields[2])?,
        attempt_id: id16(&fields[3])?,
        result: match uint(&fields[4])? {
            0 => SandboxCancellationResult::AlreadyTerminal,
            1 => SandboxCancellationResult::CancelledAndCleaned,
            _ => return Err(SandboxProviderProtocolError::FieldOutOfBounds),
        },
        terminal_spy1_digest: digest32(&fields[5])?,
        runtime_attestation_key_id: key_id(&fields[6])?,
        response_digest: digest,
        signature,
    }),
    |record: &SandboxCancelResponse| [
        text_value("SCY1"),
        uint_value(1),
        bytes_value(&record.request_id),
        bytes_value(&record.attempt_id),
        uint_value(match record.result {
            SandboxCancellationResult::AlreadyTerminal => 0,
            SandboxCancellationResult::CancelledAndCleaned => 1,
        }),
        bytes_value(&record.terminal_spy1_digest),
        text_value(&record.runtime_attestation_key_id),
    ]
);

impl SandboxCancelResponse {
    fn validate(&self, unsigned: &[Value; 7]) -> Result<(), SandboxProviderProtocolError> {
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.terminal_spy1_digest == [0; 32]
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        verify_digest("SCY1", unsigned, self.response_digest)
    }

    /// Validate the exact request and attempt identity answered by this response.
    ///
    /// # Errors
    /// Returns a closed protocol error when either record is invalid or identities differ.
    pub fn validate_for_request(
        &self,
        request: &SandboxCancelRequest,
    ) -> Result<(), SandboxProviderProtocolError> {
        request.validate()?;
        self.validate(&self.unsigned_value())?;
        validate_response_identity(
            self.request_id,
            self.attempt_id,
            &request.request,
            request.attempt_id,
        )
    }
}

signed_response_codec!(
    SandboxReconcileResponse,
    "SRY1",
    7,
    |fields: &[Value; 7], digest, signature| {
        if !bool_value(&fields[4])? {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        Ok(Self {
            request_id: id16(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            clean: true,
            reconciliation_evidence_digest: digest32(&fields[5])?,
            runtime_attestation_key_id: key_id(&fields[6])?,
            response_digest: digest,
            signature,
        })
    },
    |record: &SandboxReconcileResponse| [
        text_value("SRY1"),
        uint_value(1),
        bytes_value(&record.request_id),
        bytes_value(&record.attempt_id),
        Value::Bool(record.clean),
        bytes_value(&record.reconciliation_evidence_digest),
        text_value(&record.runtime_attestation_key_id),
    ]
);

impl SandboxReconcileResponse {
    fn validate(&self, unsigned: &[Value; 7]) -> Result<(), SandboxProviderProtocolError> {
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || !self.clean
            || self.reconciliation_evidence_digest == [0; 32]
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        verify_digest("SRY1", unsigned, self.response_digest)
    }

    /// Validate the exact request and attempt identity answered by this response.
    ///
    /// # Errors
    /// Returns a closed protocol error when either record is invalid or identities differ.
    pub fn validate_for_request(
        &self,
        request: &SandboxReconcileRequest,
    ) -> Result<(), SandboxProviderProtocolError> {
        request.validate()?;
        self.validate(&self.unsigned_value())?;
        validate_response_identity(
            self.request_id,
            self.attempt_id,
            &request.request,
            request.attempt_id,
        )
    }
}

fn validate_request_record<const N: usize>(
    request: &RequestAuthority,
    magic: &str,
    unsigned: &[Value; N],
    digest: [u8; 32],
) -> Result<(), SandboxProviderProtocolError> {
    validate_request_authority(request)?;
    verify_digest(magic, unsigned, digest)
}

fn validate_attempt_binding(
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
) -> Result<(), SandboxProviderProtocolError> {
    if attempt_id == [0; 16] || agr1_digest == [0; 32] {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_response_identity(
    response_request_id: [u8; 16],
    response_attempt_id: [u8; 16],
    request: &RequestAuthority,
    request_attempt_id: [u8; 16],
) -> Result<(), SandboxProviderProtocolError> {
    if response_request_id == request.request_id && response_attempt_id == request_attempt_id {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::InconsistentFields)
    }
}
