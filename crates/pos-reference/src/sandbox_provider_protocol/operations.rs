use ciborium::value::Value;

use super::codec::{
    array, bool_value, bytes_value, decode_document, digest32, encode, id16, key_id,
    optional_digest, optional_id16, optional_text, record_digest, require_signature, self_digested,
    signed, text_value, uint, uint_value, valid_key_id, validate_magic, verify_digest,
    verify_signature, MAX_SAFE_DETAIL_BYTES,
};
use super::{SandboxProviderProtocolError, Scy1, Sdy1, SelfDigested, Sry1, Verified};

/// Closed Sandbox Provider operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProviderOperation {
    Describe,
    Execute,
    Cancel,
    Reconcile,
}

impl SandboxProviderOperation {
    /// Returns this operation's fixed SLE1 wire code.
    #[must_use]
    pub(crate) const fn wire_code(self) -> u64 {
        match self {
            Self::Describe => 0,
            Self::Execute => 1,
            Self::Cancel => 2,
            Self::Reconcile => 3,
        }
    }

    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::Describe),
            1 => Ok(Self::Execute),
            2 => Ok(Self::Cancel),
            3 => Ok(Self::Reconcile),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
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
    const ALL: [Self; 9] = [
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

    /// Returns this local error's fixed SLE1 wire code.
    #[must_use]
    pub(crate) const fn wire_code(self) -> u64 {
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

    fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        usize::try_from(code)
            .ok()
            .and_then(|index| Self::ALL.get(index))
            .copied()
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
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
        decode_local_error(fields)
    }
}

fn decode_local_error(
    fields: &[Value; 9],
) -> Result<SandboxLocalError, SandboxProviderProtocolError> {
    let error = SandboxLocalError {
        phase: SandboxLocalErrorPhase::decode(uint(&fields[2])?)?,
        operation: decode_optional_operation(&fields[3])?,
        request_id: optional_id16(&fields[4])?,
        attempt_id: optional_id16(&fields[5])?,
        agr1_digest: optional_digest(&fields[6])?,
        code: SandboxLocalErrorCode::decode(uint(&fields[7])?)?,
        safe_detail: optional_text(&fields[8], MAX_SAFE_DETAIL_BYTES)?,
    };
    validate_local_error_shape(&error)?;
    Ok(error)
}

fn decode_optional_operation(
    value: &Value,
) -> Result<Option<SandboxProviderOperation>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        Ok(None)
    } else {
        SandboxProviderOperation::decode(uint(value)?).map(Some)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DecodedLocalErrorIdentity {
    Unidentified,
    Operation,
    Request,
    Complete,
}

const fn decoded_local_error_identity(
    error: &SandboxLocalError,
) -> Option<DecodedLocalErrorIdentity> {
    match (
        error.operation,
        error.request_id.is_some(),
        error.attempt_id.is_some(),
    ) {
        (None, false, false) => Some(DecodedLocalErrorIdentity::Unidentified),
        (Some(SandboxProviderOperation::Execute), false, false) => {
            Some(DecodedLocalErrorIdentity::Operation)
        }
        (Some(SandboxProviderOperation::Execute), true, false) => {
            Some(DecodedLocalErrorIdentity::Request)
        }
        (Some(SandboxProviderOperation::Execute), true, true) => {
            Some(DecodedLocalErrorIdentity::Complete)
        }
        _ => None,
    }
}

fn before_spx1_local_error_is_valid(
    error: &SandboxLocalError,
    identity: Option<DecodedLocalErrorIdentity>,
) -> bool {
    if error.agr1_digest.is_some() {
        return false;
    }
    match error.code {
        SandboxLocalErrorCode::PolicyUnavailable
        | SandboxLocalErrorCode::RequestAuthorityMismatch => {
            identity == Some(DecodedLocalErrorIdentity::Complete)
        }
        SandboxLocalErrorCode::InvalidSelectorRequest => identity.is_some(),
        SandboxLocalErrorCode::PayloadLimitExceeded => matches!(
            identity,
            Some(DecodedLocalErrorIdentity::Unidentified | DecodedLocalErrorIdentity::Complete)
        ),
        _ => false,
    }
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
    let identity = decoded_local_error_identity(error);
    let valid = match error.phase {
        SandboxLocalErrorPhase::BeforeSpx1 => before_spx1_local_error_is_valid(error, identity),
        SandboxLocalErrorPhase::AfterSpx1BeforeAdmission => {
            identity == Some(DecodedLocalErrorIdentity::Complete)
                && error.agr1_digest.is_none()
                && matches!(
                    error.code,
                    SandboxLocalErrorCode::ProviderUnavailable
                        | SandboxLocalErrorCode::ProviderIdentityInvalid
                        | SandboxLocalErrorCode::ControlChannelUnavailable
                        | SandboxLocalErrorCode::ProviderEvidenceInvalid
                )
        }
        SandboxLocalErrorPhase::AfterAdmission => {
            identity == Some(DecodedLocalErrorIdentity::Complete)
                && error.agr1_digest.is_some()
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

fn request_authority_value(value: &RequestAuthority) -> Value {
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

/// The signed body of an SDY1 before its digest and signature exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescribeResponseFields {
    /// The request this response answers.
    pub request_id: [u8; 16],
    /// The admitted SPM1 self-digest.
    pub spm1_digest: [u8; 32],
    /// The admitted provider binary digest.
    pub provider_binary_digest: [u8; 32],
    /// The admitted HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// The active APT1 digest.
    pub active_apt1_digest: [u8; 32],
    /// Provider runtime-attestation key ID.
    pub runtime_attestation_key_id: String,
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
    response_digest: [u8; 32],
    signature: [u8; 64],
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

/// The signed body of an SCY1 before its digest and signature exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCancelResponseFields {
    /// The SCQ1 request this response answers.
    pub request_id: [u8; 16],
    /// The attempt the request named.
    pub attempt_id: [u8; 16],
    /// `0`: the attempt was already terminal and is unchanged; `1`: this
    /// request caused its cancellation and complete cleanup.
    pub result: SandboxCancellationResult,
    /// The self-digest of the attempt's terminal SPY1, which both results
    /// bind.
    pub terminal_spy1_digest: [u8; 32],
    /// Provider runtime-attestation key ID.
    pub runtime_attestation_key_id: String,
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

/// The signed body of an SRY1 before its digest and signature exist; its
/// `clean` field is the literal `true`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReconcileResponseFields {
    /// The SRQ1 request this response answers.
    pub request_id: [u8; 16],
    /// The attempt the request named.
    pub attempt_id: [u8; 16],
    /// The digest of the attempt's retained `reconciliation-evidence-v1`
    /// (ADR-069 R15 §3.1).
    pub reconciliation_evidence_digest: [u8; 32],
    /// Provider runtime-attestation key ID.
    pub runtime_attestation_key_id: String,
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
    pub(crate) fn canonical(
        request: RequestAuthority,
    ) -> Result<(Self, Vec<u8>), SandboxProviderProtocolError> {
        validate_request_authority(&request)?;
        let unsigned = Value::Array(vec![
            text_value("SDQ1"),
            uint_value(1),
            request_authority_value(&request),
        ]);
        let request_digest = record_digest("SDQ1", &unsigned)?;
        let bytes = encode(&Value::Array(vec![unsigned, bytes_value(&request_digest)]))?;
        let record = Self {
            request,
            request_digest,
        };
        record.validate()?;
        Ok((record, bytes))
    }

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
    /// Build the exact canonical SCQ1 bytes of one attempt cancellation.
    pub(crate) fn canonical(
        request: RequestAuthority,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<(Self, Vec<u8>), SandboxProviderProtocolError> {
        let (request_digest, bytes) =
            canonical_attempt_request("SCQ1", &request, attempt_id, agr1_digest)?;
        Ok((
            Self {
                request,
                attempt_id,
                agr1_digest,
                request_digest,
            },
            bytes,
        ))
    }

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
    /// Build the exact canonical SRQ1 bytes of one attempt reconciliation.
    pub(crate) fn canonical(
        request: RequestAuthority,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<(Self, Vec<u8>), SandboxProviderProtocolError> {
        let (request_digest, bytes) =
            canonical_attempt_request("SRQ1", &request, attempt_id, agr1_digest)?;
        Ok((
            Self {
                request,
                attempt_id,
                agr1_digest,
                request_digest,
            },
            bytes,
        ))
    }

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
    |record: &SandboxDescribeResponse| describe_unsigned_value(&record.fields())
);

/// The SDY1 field bounds: nonzero identities and a valid key ID.
fn validate_describe_fields(
    fields: &SandboxDescribeResponseFields,
) -> Result<(), SandboxProviderProtocolError> {
    if fields.request_id == [0; 16]
        || [
            fields.spm1_digest,
            fields.provider_binary_digest,
            fields.hcp1_digest,
            fields.active_apt1_digest,
        ]
        .contains(&[0; 32])
        || !valid_key_id(&fields.runtime_attestation_key_id)
    {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn describe_unsigned_value(fields: &SandboxDescribeResponseFields) -> [Value; 8] {
    [
        text_value("SDY1"),
        uint_value(1),
        bytes_value(&fields.request_id),
        bytes_value(&fields.spm1_digest),
        bytes_value(&fields.provider_binary_digest),
        bytes_value(&fields.hcp1_digest),
        bytes_value(&fields.active_apt1_digest),
        text_value(&fields.runtime_attestation_key_id),
    ]
}

impl SandboxDescribeResponse {
    /// Validate the fields and self-digest them: the only input the
    /// runtime-attestation signer accepts for an SDY1 (ADR-069 R9 §5).
    ///
    /// # Errors
    /// Rejects a zero identity or an invalid key ID.
    pub fn self_digested(
        fields: SandboxDescribeResponseFields,
    ) -> Result<SelfDigested<Sdy1>, SandboxProviderProtocolError> {
        validate_describe_fields(&fields)
            .and_then(|()| {
                record_digest(
                    "SDY1",
                    &Value::Array(describe_unsigned_value(&fields).to_vec()),
                )
            })
            .map(|digest| SelfDigested::sealed(fields, digest))
    }

    /// The signed record of a signature that verified under `key`, the
    /// admitted runtime-attestation key.
    ///
    /// # Errors
    /// `SignatureInvalid` when the signature verified under another key.
    pub fn new(
        verified: Verified<Sdy1>,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxProviderProtocolError> {
        if verified.key() == key {
            let (fields, response_digest, signature) = verified.into_parts();
            Ok(Self {
                request_id: fields.request_id,
                spm1_digest: fields.spm1_digest,
                provider_binary_digest: fields.provider_binary_digest,
                hcp1_digest: fields.hcp1_digest,
                active_apt1_digest: fields.active_apt1_digest,
                runtime_attestation_key_id: fields.runtime_attestation_key_id,
                response_digest,
                signature,
            })
        } else {
            Err(SandboxProviderProtocolError::SignatureInvalid)
        }
    }

    /// Exact canonical SDY1 bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        encode(&Value::Array(vec![
            Value::Array(self.unsigned_value().to_vec()),
            bytes_value(&self.response_digest),
            bytes_value(&self.signature),
        ]))
    }

    /// The SDY1 self-digest.
    #[must_use]
    pub const fn response_digest(&self) -> [u8; 32] {
        self.response_digest
    }

    /// The runtime-attestation signature over the self-digest.
    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    fn fields(&self) -> SandboxDescribeResponseFields {
        SandboxDescribeResponseFields {
            request_id: self.request_id,
            spm1_digest: self.spm1_digest,
            provider_binary_digest: self.provider_binary_digest,
            hcp1_digest: self.hcp1_digest,
            active_apt1_digest: self.active_apt1_digest,
            runtime_attestation_key_id: self.runtime_attestation_key_id.clone(),
        }
    }

    fn validate(&self, unsigned: &[Value; 8]) -> Result<(), SandboxProviderProtocolError> {
        validate_describe_fields(&self.fields())?;
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

/// SCY1's unsigned prefix: `["SCY1", 1, request, attempt, result, SPY1
/// digest, key ID]` (ADR-069 §10).
fn cancel_unsigned_value(fields: &SandboxCancelResponseFields) -> [Value; 7] {
    [
        text_value("SCY1"),
        uint_value(1),
        bytes_value(&fields.request_id),
        bytes_value(&fields.attempt_id),
        uint_value(match fields.result {
            SandboxCancellationResult::AlreadyTerminal => 0,
            SandboxCancellationResult::CancelledAndCleaned => 1,
        }),
        bytes_value(&fields.terminal_spy1_digest),
        text_value(&fields.runtime_attestation_key_id),
    ]
}

impl SandboxCancelResponse {
    /// Validate the fields and self-digest them: the only input the
    /// runtime-attestation signer accepts for an SCY1 (ADR-069 R9 §5).
    ///
    /// # Errors
    /// Rejects a zero identity or SPY1 digest and an invalid key ID.
    pub fn self_digested(
        fields: SandboxCancelResponseFields,
    ) -> Result<SelfDigested<Scy1>, SandboxProviderProtocolError> {
        if fields.request_id == [0; 16]
            || fields.attempt_id == [0; 16]
            || fields.terminal_spy1_digest == [0; 32]
            || !valid_key_id(&fields.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        record_digest(
            "SCY1",
            &Value::Array(cancel_unsigned_value(&fields).to_vec()),
        )
        .map(|digest| SelfDigested::sealed(fields, digest))
    }

    /// The signed record of a signature that verified under `key`, the
    /// admitted runtime-attestation key.
    ///
    /// # Errors
    /// `SignatureInvalid` when the signature verified under another key.
    pub fn new(
        verified: Verified<Scy1>,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxProviderProtocolError> {
        if verified.key() == key {
            let (fields, response_digest, signature) = verified.into_parts();
            Ok(Self {
                request_id: fields.request_id,
                attempt_id: fields.attempt_id,
                result: fields.result,
                terminal_spy1_digest: fields.terminal_spy1_digest,
                runtime_attestation_key_id: fields.runtime_attestation_key_id,
                response_digest,
                signature,
            })
        } else {
            Err(SandboxProviderProtocolError::SignatureInvalid)
        }
    }

    /// Exact canonical SCY1 bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        encode(&Value::Array(vec![
            Value::Array(self.unsigned_value().to_vec()),
            bytes_value(&self.response_digest),
            bytes_value(&self.signature),
        ]))
    }

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

/// SRY1's unsigned prefix: `["SRY1", 1, request, attempt, true, evidence
/// digest, key ID]` (ADR-069 §10).
fn reconcile_unsigned_value(fields: &SandboxReconcileResponseFields) -> [Value; 7] {
    [
        text_value("SRY1"),
        uint_value(1),
        bytes_value(&fields.request_id),
        bytes_value(&fields.attempt_id),
        Value::Bool(true),
        bytes_value(&fields.reconciliation_evidence_digest),
        text_value(&fields.runtime_attestation_key_id),
    ]
}

impl SandboxReconcileResponse {
    /// Validate the fields and self-digest them: the only input the
    /// runtime-attestation signer accepts for an SRY1 (ADR-069 R9 §5).
    ///
    /// # Errors
    /// Rejects a zero identity or evidence digest and an invalid key ID.
    pub fn self_digested(
        fields: SandboxReconcileResponseFields,
    ) -> Result<SelfDigested<Sry1>, SandboxProviderProtocolError> {
        if fields.request_id == [0; 16]
            || fields.attempt_id == [0; 16]
            || fields.reconciliation_evidence_digest == [0; 32]
            || !valid_key_id(&fields.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        record_digest(
            "SRY1",
            &Value::Array(reconcile_unsigned_value(&fields).to_vec()),
        )
        .map(|digest| SelfDigested::sealed(fields, digest))
    }

    /// The signed record of a signature that verified under `key`, the
    /// admitted runtime-attestation key.
    ///
    /// # Errors
    /// `SignatureInvalid` when the signature verified under another key.
    pub fn new(
        verified: Verified<Sry1>,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxProviderProtocolError> {
        if verified.key() == key {
            let (fields, response_digest, signature) = verified.into_parts();
            Ok(Self {
                request_id: fields.request_id,
                attempt_id: fields.attempt_id,
                clean: true,
                reconciliation_evidence_digest: fields.reconciliation_evidence_digest,
                runtime_attestation_key_id: fields.runtime_attestation_key_id,
                response_digest,
                signature,
            })
        } else {
            Err(SandboxProviderProtocolError::SignatureInvalid)
        }
    }

    /// Exact canonical SRY1 bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        encode(&Value::Array(vec![
            Value::Array(self.unsigned_value().to_vec()),
            bytes_value(&self.response_digest),
            bytes_value(&self.signature),
        ]))
    }

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

/// SCQ1 and SRQ1 share one shape: `[magic, 1, request, attempt, AGR1 digest]`
/// and a trailing self-digest (ADR-069 §10).
fn canonical_attempt_request(
    magic: &str,
    request: &RequestAuthority,
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
) -> Result<([u8; 32], Vec<u8>), SandboxProviderProtocolError> {
    validate_request_authority(request)?;
    validate_attempt_binding(attempt_id, agr1_digest)?;
    let unsigned = Value::Array(vec![
        text_value(magic),
        uint_value(1),
        request_authority_value(request),
        bytes_value(&attempt_id),
        bytes_value(&agr1_digest),
    ]);
    let request_digest = record_digest(magic, &unsigned)?;
    encode(&Value::Array(vec![unsigned, bytes_value(&request_digest)]))
        .map(|bytes| (request_digest, bytes))
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn describe_request_constructor_round_trips_and_rejects_zero_authority(
    ) -> Result<(), SandboxProviderProtocolError> {
        let authority = RequestAuthority {
            request_id: [1; 16],
            apt1_digest: [2; 32],
            policy_epoch: 3,
            nonce: [4; 16],
        };
        let (request, bytes) = SandboxDescribeRequest::canonical(authority.clone())?;
        assert_eq!(request.request, authority);
        assert_eq!(
            SandboxDescribeRequest::from_canonical_cbor(&bytes),
            Ok(request)
        );

        for invalid in [
            RequestAuthority {
                request_id: [0; 16],
                ..authority.clone()
            },
            RequestAuthority {
                apt1_digest: [0; 32],
                ..authority.clone()
            },
            RequestAuthority {
                nonce: [0; 16],
                ..authority
            },
        ] {
            assert!(SandboxDescribeRequest::canonical(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn selector_wire_codes_cover_every_operation_and_local_failure() {
        for (operation, code) in [
            (SandboxProviderOperation::Describe, 0),
            (SandboxProviderOperation::Execute, 1),
            (SandboxProviderOperation::Cancel, 2),
            (SandboxProviderOperation::Reconcile, 3),
        ] {
            assert_eq!(operation.wire_code(), code);
            assert_eq!(SandboxProviderOperation::decode(code), Ok(operation));
        }
        for (error, code) in [
            (SandboxLocalErrorCode::ProviderUnavailable, 0),
            (SandboxLocalErrorCode::ProviderIdentityInvalid, 1),
            (SandboxLocalErrorCode::PolicyUnavailable, 2),
            (SandboxLocalErrorCode::ControlChannelUnavailable, 3),
            (SandboxLocalErrorCode::InvalidSelectorRequest, 4),
            (SandboxLocalErrorCode::RequestAuthorityMismatch, 5),
            (SandboxLocalErrorCode::PayloadLimitExceeded, 6),
            (SandboxLocalErrorCode::ProviderTerminalUnavailable, 7),
            (SandboxLocalErrorCode::ProviderEvidenceInvalid, 8),
        ] {
            assert_eq!(error.wire_code(), code);
            assert_eq!(SandboxLocalErrorCode::decode(code), Ok(error));
        }
    }
}
