//! Immutable RVR1 verification requests defined by ADR-058.

use crate::domain_digest;
use crate::ReproducibilityClassV1;
use ciborium::value::Value;
use std::io::Cursor;

/// Magic for the immutable reproducibility-verification request record.
pub const REPRO_VERIFICATION_REQUEST_MAGIC_V1: &str = "RVR1";
/// Maximum encoded size of an RVR1 request.
pub const MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1: usize = 16 * 1024;
/// Maximum report budget an RVR1 request may grant to a verifier.
pub const MAX_REPORT_BYTES_V1: u64 = 16 * 1024;

const FIELD_COUNT: usize = 10;
const MAX_NESTING_DEPTH: u8 = 2;

/// Closed safe errors exposed by the RVR1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReproVerificationRequestContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic, schema version, or enum code is not supported.
    UnsupportedVersion,
    /// A required reference or encoded record exceeds its specified bound.
    FieldOutOfBounds,
}

impl std::fmt::Display for ReproVerificationRequestContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid RVR1 verification request encoding",
            Self::UnsupportedVersion => "unsupported RVR1 verification request version",
            Self::FieldOutOfBounds => "RVR1 verification request field is out of bounds",
        })
    }
}

impl std::error::Error for ReproVerificationRequestContractErrorV1 {}

/// A bounded request for verification of one immutable reproducibility closure.
///
/// The six digest fields are references to already materialized records or
/// closures. RVR1 does not load those records or admit their trust roots; those
/// operations belong to the later verification-preflight boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReproVerificationRequestV1 {
    /// Digest identifying the caller's verification request.
    pub request_digest: [u8; 32],
    /// Digest identifying the `ReproManifest` to verify.
    pub manifest_digest: [u8; 32],
    /// Reproducibility class requested for this verification.
    pub reproducibility_class: ReproducibilityClassV1,
    /// Digest identifying the named EPF1 execution profile.
    pub execution_profile_digest: [u8; 32],
    /// Digest identifying the TPS1 trust-policy snapshot.
    pub trust_policy_snapshot_digest: [u8; 32],
    /// Digest identifying the complete artifact closure.
    pub artifact_closure_digest: [u8; 32],
    /// Digest identifying the evaluator and its report authority.
    pub evaluator_digest: [u8; 32],
    /// Maximum report bytes the verifier may emit.
    pub report_bytes_limit: u64,
}

impl ReproVerificationRequestV1 {
    /// Validate RVR1 references, class, and report budget.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when a digest reference is zero or the
    /// report budget is outside the accepted range.
    pub fn validate(&self) -> Result<(), ReproVerificationRequestContractErrorV1> {
        validate_fields(self)
    }

    /// Encode this request as an exact deterministic-CBOR RVR1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when a request field is invalid or encoding
    /// fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ReproVerificationRequestContractErrorV1> {
        validate_fields(self)?;
        encode_value(&encode_request(self))
    }

    /// Decode and validate exact canonical RVR1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// structurally invalid RVR1 bytes.
    pub fn from_canonical_cbor(
        bytes: &[u8],
    ) -> Result<Self, ReproVerificationRequestContractErrorV1> {
        if bytes.len() > MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1 {
            return Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds);
        }
        decode_value(bytes)
            .and_then(|value| decode_request(&value))
            .and_then(|request| request.validate().map(|()| request))
    }

    /// Compute the domain-separated BLAKE3 digest of the complete RVR1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the request is structurally invalid or
    /// cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], ReproVerificationRequestContractErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| domain_digest(b"PiglorOS.ReproVerificationRequest.v1", &bytes))
    }
}

fn validate_fields(
    request: &ReproVerificationRequestV1,
) -> Result<(), ReproVerificationRequestContractErrorV1> {
    if [
        request.request_digest,
        request.manifest_digest,
        request.execution_profile_digest,
        request.trust_policy_snapshot_digest,
        request.artifact_closure_digest,
        request.evaluator_digest,
    ]
    .contains(&[0; 32])
        || request.report_bytes_limit == 0
        || request.report_bytes_limit > MAX_REPORT_BYTES_V1
    {
        return Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds);
    }
    Ok(())
}

fn encode_request(request: &ReproVerificationRequestV1) -> Value {
    Value::Array(vec![
        Value::Text(REPRO_VERIFICATION_REQUEST_MAGIC_V1.to_owned()),
        Value::Integer(1_u64.into()),
        digest(&request.request_digest),
        digest(&request.manifest_digest),
        Value::Integer(reproducibility_code(request.reproducibility_class).into()),
        digest(&request.execution_profile_digest),
        digest(&request.trust_policy_snapshot_digest),
        digest(&request.artifact_closure_digest),
        digest(&request.evaluator_digest),
        Value::Integer(request.report_bytes_limit.into()),
    ])
}

fn decode_request(
    value: &Value,
) -> Result<ReproVerificationRequestV1, ReproVerificationRequestContractErrorV1> {
    let fields = array(value)?;
    let magic = text_value(&fields[0])?;
    let version = uint_value(&fields[1])?;
    if magic != REPRO_VERIFICATION_REQUEST_MAGIC_V1 || version != 1 {
        return Err(ReproVerificationRequestContractErrorV1::UnsupportedVersion);
    }
    Ok(ReproVerificationRequestV1 {
        request_digest: digest_value(&fields[2])?,
        manifest_digest: digest_value(&fields[3])?,
        reproducibility_class: decode_reproducibility_class(&fields[4])?,
        execution_profile_digest: digest_value(&fields[5])?,
        trust_policy_snapshot_digest: digest_value(&fields[6])?,
        artifact_closure_digest: digest_value(&fields[7])?,
        evaluator_digest: digest_value(&fields[8])?,
        report_bytes_limit: uint_value(&fields[9])?,
    })
}

fn decode_reproducibility_class(
    value: &Value,
) -> Result<ReproducibilityClassV1, ReproVerificationRequestContractErrorV1> {
    match uint_value(value)? {
        0 => Ok(ReproducibilityClassV1::RecordedReplay),
        1 => Ok(ReproducibilityClassV1::ProfileRecomputation),
        2 => Ok(ReproducibilityClassV1::CrossProfileConformance),
        3 => Ok(ReproducibilityClassV1::LiveUnverified),
        _ => Err(ReproVerificationRequestContractErrorV1::UnsupportedVersion),
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ReproVerificationRequestContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ReproVerificationRequestContractErrorV1::InvalidEncoding)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ReproVerificationRequestContractErrorV1> {
    preflight_cbor(bytes)?;
    ciborium::from_reader(Cursor::new(bytes))
        .map_err(|_| ReproVerificationRequestContractErrorV1::InvalidEncoding)
        .and_then(|value| {
            encode_value(&value).and_then(|canonical| {
                if canonical == bytes {
                    Ok(value)
                } else {
                    Err(ReproVerificationRequestContractErrorV1::InvalidEncoding)
                }
            })
        })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), ReproVerificationRequestContractErrorV1> {
    crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, FIELD_COUNT as u64 + 1, false).map_err(
        |error| match error {
            crate::CborPreflightError::InvalidEncoding => {
                ReproVerificationRequestContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                ReproVerificationRequestContractErrorV1::FieldOutOfBounds
            }
        },
    )
}

fn array(value: &Value) -> Result<&[Value], ReproVerificationRequestContractErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == FIELD_COUNT => Ok(fields),
        _ => Err(ReproVerificationRequestContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, ReproVerificationRequestContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(ReproVerificationRequestContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, ReproVerificationRequestContractErrorV1> {
    match value {
        Value::Integer(value) => u64::try_from(*value)
            .map_err(|_| ReproVerificationRequestContractErrorV1::InvalidEncoding),
        _ => Err(ReproVerificationRequestContractErrorV1::InvalidEncoding),
    }
}

fn digest_value(value: &Value) -> Result<[u8; 32], ReproVerificationRequestContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| ReproVerificationRequestContractErrorV1::InvalidEncoding),
        _ => Err(ReproVerificationRequestContractErrorV1::InvalidEncoding),
    }
}

fn digest(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

const fn reproducibility_code(value: ReproducibilityClassV1) -> u64 {
    match value {
        ReproducibilityClassV1::RecordedReplay => 0,
        ReproducibilityClassV1::ProfileRecomputation => 1,
        ReproducibilityClassV1::CrossProfileConformance => 2,
        ReproducibilityClassV1::LiveUnverified => 3,
    }
}
