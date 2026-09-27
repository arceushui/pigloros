//! Canonical Sandbox Provider records, grouped by protocol responsibility.

mod execution;
mod payload;
mod receipt;
mod terminal;

pub use execution::{
    AdmissionAuthorityV1, AdmissionGrantV1, NetworkExchangePlanV1, SandboxExecuteRequestV1,
};
pub use payload::{
    PayloadDescriptorV1, PayloadDirectionV1, PayloadStreamValidatorV1, SandboxPayloadChunkV1,
};
pub use receipt::{ReceiptAuthorityV1, SandboxProviderReceiptV1};
pub use terminal::{
    SandboxProviderErrorCodeV1, SandboxProviderErrorV1, SandboxProviderResultV1,
    SandboxTerminalOutcomeV1,
};

use super::codec::{array, encode, fixed, uint, value_bytes, value_uint};
use super::SandboxContractErrorV1;
use ciborium::value::Value;

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

pub(super) fn request_authority_value(value: &RequestAuthorityV1) -> Value {
    Value::Array(vec![
        value_bytes(&value.request_id),
        value_bytes(&value.apt1_digest),
        value_uint(value.policy_epoch),
        value_bytes(&value.nonce),
    ])
}

pub(super) fn decode_request_authority(
    value: &Value,
) -> Result<RequestAuthorityV1, SandboxContractErrorV1> {
    let fields = array::<4>(value)?;
    Ok(RequestAuthorityV1 {
        request_id: fixed(&fields[0])?,
        apt1_digest: fixed(&fields[1])?,
        policy_epoch: uint(&fields[2])?,
        nonce: fixed(&fields[3])?,
    })
}

pub(super) fn validate_request_authority(
    value: &RequestAuthorityV1,
) -> Result<(), SandboxContractErrorV1> {
    if value.request_id == [0; 16] || value.apt1_digest == [0; 32] || value.nonce == [0; 16] {
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
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

fn decode_digest_list(value: &Value) -> Result<Vec<[u8; 32]>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values.iter().map(fixed).collect()
}
