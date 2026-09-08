//! Independent strict decoder for the ADR-069 Sandbox Provider protocol.
//!
//! This module deliberately does not depend on `pos-conformance`. It gives the
//! reference evaluator a second implementation of the public wire contract.

mod admission;
mod audit;
mod authority;
mod codec;
mod execution;
mod operations;
mod policy;
mod revocation;
mod trust;

pub use policy::{SandboxAdministratorPolicy, SandboxPolicySelection};
pub use revocation::{SandboxRevocationSnapshot, SandboxTrustError};
pub use trust::{SandboxTrustCertificate, SandboxTrustKey, SandboxTrustRole, SandboxTrustSnapshot};

pub use admission::{
    AdmittedSandboxImage, AdmittedSandboxProvider, HostCapabilityProfile, HostFeatureProof,
    ProviderConformanceReport, SandboxAdmissionError, SandboxProviderAdmissionInputs,
};
pub use audit::SandboxAuditRecord;
pub use authority::{
    LaunchPolicy, NetworkCapability, PartitionDescriptor, PartitionRole, Pkcs7Proof,
    ProviderCapability, SandboxArchitecture, SandboxExecutionMode, SandboxLimit,
    SandboxProviderManifest, SandboxSyscallSet, SignedImageManifest,
};
pub use execution::{
    AdmissionAuthority, AdmissionGrant, ExecuteAuthority, NetworkExchangePlan, PayloadDescriptor,
    PayloadDirection, PayloadStreamValidator, ReceiptAuthority, SandboxExecuteRequest,
    SandboxPayloadChunk, SandboxProviderError, SandboxProviderErrorCode, SandboxProviderReceipt,
    SandboxProviderResult, SandboxTerminalOutcome,
};
pub use operations::{
    RequestAuthority, SandboxCancelRequest, SandboxCancelResponse, SandboxCancellationResult,
    SandboxDescribeRequest, SandboxDescribeResponse, SandboxLocalError, SandboxLocalErrorCode,
    SandboxProviderOperation, SandboxReconcileRequest, SandboxReconcileResponse,
};

/// Closed failures produced before a provider operation is trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxProviderProtocolError {
    /// CBOR is malformed, forbidden, noncanonical, or has the wrong shape.
    #[error("invalid canonical sandbox-provider encoding")]
    InvalidEncoding,
    /// Record magic or version is not the accepted contract.
    #[error("unsupported sandbox-provider record version")]
    UnsupportedVersion,
    /// A scalar, byte string, text string, or collection violates its bound.
    #[error("sandbox-provider field is out of bounds")]
    FieldOutOfBounds,
    /// A set-like collection is not strictly sorted and unique.
    #[error("sandbox-provider collection is not canonically ordered")]
    NonCanonicalOrder,
    /// Fields that must agree or form a closed union do not agree.
    #[error("sandbox-provider fields are inconsistent")]
    InconsistentFields,
    /// A self-digest does not bind the canonical unsigned prefix.
    #[error("sandbox-provider self-digest does not match")]
    DigestMismatch,
    /// Signature bytes are absent or fail Ed25519 verification.
    #[error("sandbox-provider signature is invalid")]
    SignatureInvalid,
}
