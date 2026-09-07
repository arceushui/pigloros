//! Provider-neutral Sandbox Provider wire contracts from ADR-069.
//!
//! This module contains only canonical records and validation. Provider
//! selection, trust policy, installation, and Linux substrate behavior belong
//! to later implementation tickets.

mod authority;
mod codec;
mod operations;
mod protocol;

pub use authority::{
    LaunchPolicyV1, PartitionDescriptorV1, PartitionRoleV1, Pkcs7ProofV1,
    SandboxProviderManifestV1, SignedImageManifestV1,
};
pub use operations::{
    SandboxCancelRequestV1, SandboxCancelResponseV1, SandboxCancelResultV1,
    SandboxDescribeRequestV1, SandboxDescribeResponseV1, SandboxLocalErrorCodeV1,
    SandboxLocalErrorV1, SandboxProviderOperationV1, SandboxReconcileRequestV1,
    SandboxReconcileResponseV1,
};
pub use protocol::{
    AdapterInputV1, AdmissionAuthorityV1, AdmissionGrantV1, NetworkExchangePlanV1,
    ReceiptAuthorityV1, RequestAuthorityV1, SandboxExecuteRequestV1, SandboxOutputV1,
    SandboxProviderErrorCodeV1, SandboxProviderErrorV1, SandboxProviderReceiptV1,
    SandboxProviderResultV1, SandboxTerminalOutcomeV1,
};

use thiserror::Error;

/// Largest canonical Sandbox Provider control document.
pub const MAX_SANDBOX_PROVIDER_DOCUMENT_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of capabilities or exchanges in one control document.
pub const MAX_SANDBOX_PROVIDER_ENTRIES_V1: usize = 256;
/// Canonical upper bound for a Sandbox Release Launcher response wait.
pub const SANDBOX_RELEASE_TIMEOUT_SECONDS_V1: u64 = 30;

/// Supported provider host architecture.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SandboxArchitectureV1 {
    /// AMD64/x86-64.
    X86_64,
    /// 64-bit ARM/AArch64.
    Aarch64,
}

impl SandboxArchitectureV1 {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::X86_64 => 0,
            Self::Aarch64 => 1,
        }
    }

    pub(crate) const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::X86_64),
            1 => Ok(Self::Aarch64),
            _ => Err(SandboxContractErrorV1::InvalidEncoding),
        }
    }
}

/// One exact provider capability descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapabilityV1 {
    /// Stable provider-neutral capability identifier.
    pub capability_id: String,
    /// Capability contract version.
    pub capability_version: u64,
    /// Minimum admitted strength.
    pub minimum_strength: u64,
}

/// One exact resource limit selected by LPS1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxLimitV1 {
    /// Closed ADR-069 limit discriminant in `0..=15`.
    pub limit_id: u8,
    /// Nonzero selected ceiling.
    pub value: u64,
}

/// One exact TCP exchange capability selected by LPS1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkCapabilityV1 {
    /// Stable provider-neutral capability identifier.
    pub capability_id: String,
    /// Exact IPv4 or IPv6 destination bytes.
    pub address: Vec<u8>,
    /// Nonzero destination TCP port.
    pub destination_port: u16,
    /// Maximum request bytes.
    pub request_maximum: u64,
    /// Maximum response bytes.
    pub response_maximum: u64,
}

/// Closed validation failures shared by every Sandbox Provider record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SandboxContractErrorV1 {
    /// CBOR is malformed, noncanonical, or has a forbidden shape.
    #[error("sandbox provider encoding is invalid")]
    InvalidEncoding,
    /// Magic or schema version is not supported.
    #[error("sandbox provider contract version is unsupported")]
    UnsupportedVersion,
    /// A scalar, collection, or document exceeds its exact bound.
    #[error("sandbox provider field is out of bounds")]
    FieldOutOfBounds,
    /// A collection is duplicated or not canonically ordered.
    #[error("sandbox provider collection is not canonically ordered")]
    NonCanonicalOrder,
    /// A self-digest or content digest does not match.
    #[error("sandbox provider digest does not match")]
    DigestMismatch,
    /// An Ed25519 signature is malformed or does not verify.
    #[error("sandbox provider signature is invalid")]
    SignatureInvalid,
    /// Cross-field identities or terminal-union fields disagree.
    #[error("sandbox provider record fields are inconsistent")]
    InconsistentFields,
}
