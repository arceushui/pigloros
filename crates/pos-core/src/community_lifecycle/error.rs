//! Closed outer lifecycle error codec; these values grant no authority.

/// Exact ADR-129 outer lifecycle errors, encoded as a one-field CBOR array.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommunityLifecycleErrorV1 {
    /// Malformed, nonpreferred, unknown-enum or trailing encoding.
    #[error("invalid community lifecycle encoding")]
    InvalidEncoding,
    /// An unsupported record wire version.
    #[error("unsupported community lifecycle version")]
    UnsupportedVersion,
    /// A record or field exceeds its declared bound.
    #[error("community lifecycle bounds exceeded")]
    BoundsExceeded,
    /// A required identity or binding is invalid.
    #[error("invalid community lifecycle binding")]
    InvalidBinding,
    /// An operation identity was reused with different bound content.
    #[error("community lifecycle conflict")]
    Conflict,
    /// The requested generation is not the current admitted generation.
    #[error("stale community generation")]
    StaleGeneration,
    /// The expected committed frontier or complete head is stale.
    #[error("stale community frontier")]
    StaleFrontier,
    /// An original attempt remains unresolved.
    #[error("community pass unresolved")]
    PassUnresolved,
    /// The sole fresh execution permit was already consumed.
    #[error("community pass permit consumed")]
    PermitConsumed,
    /// An active durable reason denies execution.
    #[error("community implementation quarantined")]
    Quarantined,
    /// Current independent admission denies the operation.
    #[error("community admission denied")]
    AdmissionDenied,
    /// Current protected use cannot be authorized.
    #[error("community protected use denied")]
    ProtectedUseDenied,
    /// Required original evidence cannot be obtained.
    #[error("community evidence unavailable")]
    EvidenceUnavailable,
    /// Required original evidence is past its fixed admitted horizon.
    #[error("community evidence expired")]
    EvidenceExpired,
    /// Required cumulative capacity cannot cover the operation.
    #[error("community lifecycle capacity exhausted")]
    CapacityExhausted,
    /// An operation already owns the shared lifecycle context.
    #[error("community lifecycle operation active")]
    OperationActive,
    /// The original outcome is unknown; this never permits re-execution.
    #[error("community lifecycle outcome unknown")]
    OutcomeUnknown,
    /// The actual context is closed, including native safety quarantine.
    #[error("community lifecycle context closed")]
    ContextClosed,
    /// The concrete storage owner is unavailable.
    #[error("community lifecycle storage unavailable")]
    StorageUnavailable,
    /// Mandatory base recording cannot be retained before Reserve.
    #[error("community lifecycle recording unavailable")]
    RecordingUnavailable,
}

impl CommunityLifecycleErrorV1 {
    /// Encode the accepted fixed code; Rust enum discriminants are not wire data.
    #[must_use]
    pub const fn to_canonical_cbor(self) -> [u8; 2] {
        use CommunityLifecycleErrorV1 as E;
        let code = match self {
            E::InvalidEncoding => 0,
            E::UnsupportedVersion => 1,
            E::BoundsExceeded => 2,
            E::InvalidBinding => 3,
            E::Conflict => 4,
            E::StaleGeneration => 5,
            E::StaleFrontier => 6,
            E::PassUnresolved => 7,
            E::PermitConsumed => 8,
            E::Quarantined => 9,
            E::AdmissionDenied => 10,
            E::ProtectedUseDenied => 11,
            E::EvidenceUnavailable => 12,
            E::EvidenceExpired => 13,
            E::CapacityExhausted => 14,
            E::OperationActive => 15,
            E::OutcomeUnknown => 16,
            E::ContextClosed => 17,
            E::StorageUnavailable => 18,
            E::RecordingUnavailable => 19,
        };
        [0x81, code]
    }

    /// Decode the exact one-field preferred CBOR error array.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for an unknown code or any other encoding.
    pub const fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Self> {
        use CommunityLifecycleErrorV1 as E;
        match bytes {
            [0x81, 0] => Ok(E::InvalidEncoding),
            [0x81, 1] => Ok(E::UnsupportedVersion),
            [0x81, 2] => Ok(E::BoundsExceeded),
            [0x81, 3] => Ok(E::InvalidBinding),
            [0x81, 4] => Ok(E::Conflict),
            [0x81, 5] => Ok(E::StaleGeneration),
            [0x81, 6] => Ok(E::StaleFrontier),
            [0x81, 7] => Ok(E::PassUnresolved),
            [0x81, 8] => Ok(E::PermitConsumed),
            [0x81, 9] => Ok(E::Quarantined),
            [0x81, 10] => Ok(E::AdmissionDenied),
            [0x81, 11] => Ok(E::ProtectedUseDenied),
            [0x81, 12] => Ok(E::EvidenceUnavailable),
            [0x81, 13] => Ok(E::EvidenceExpired),
            [0x81, 14] => Ok(E::CapacityExhausted),
            [0x81, 15] => Ok(E::OperationActive),
            [0x81, 16] => Ok(E::OutcomeUnknown),
            [0x81, 17] => Ok(E::ContextClosed),
            [0x81, 18] => Ok(E::StorageUnavailable),
            [0x81, 19] => Ok(E::RecordingUnavailable),
            _ => Err(E::InvalidEncoding),
        }
    }
}
