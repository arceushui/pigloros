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
        let code = match self {
            Self::InvalidEncoding => 0,
            Self::UnsupportedVersion => 1,
            Self::BoundsExceeded => 2,
            Self::InvalidBinding => 3,
            Self::Conflict => 4,
            Self::StaleGeneration => 5,
            Self::StaleFrontier => 6,
            Self::PassUnresolved => 7,
            Self::PermitConsumed => 8,
            Self::Quarantined => 9,
            Self::AdmissionDenied => 10,
            Self::ProtectedUseDenied => 11,
            Self::EvidenceUnavailable => 12,
            Self::EvidenceExpired => 13,
            Self::CapacityExhausted => 14,
            Self::OperationActive => 15,
            Self::OutcomeUnknown => 16,
            Self::ContextClosed => 17,
            Self::StorageUnavailable => 18,
            Self::RecordingUnavailable => 19,
        };
        [0x81, code]
    }

    /// Decode the exact one-field preferred CBOR error array.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for an unknown code or any other encoding.
    pub const fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Self> {
        match bytes {
            [0x81, 0] => Ok(Self::InvalidEncoding),
            [0x81, 1] => Ok(Self::UnsupportedVersion),
            [0x81, 2] => Ok(Self::BoundsExceeded),
            [0x81, 3] => Ok(Self::InvalidBinding),
            [0x81, 4] => Ok(Self::Conflict),
            [0x81, 5] => Ok(Self::StaleGeneration),
            [0x81, 6] => Ok(Self::StaleFrontier),
            [0x81, 7] => Ok(Self::PassUnresolved),
            [0x81, 8] => Ok(Self::PermitConsumed),
            [0x81, 9] => Ok(Self::Quarantined),
            [0x81, 10] => Ok(Self::AdmissionDenied),
            [0x81, 11] => Ok(Self::ProtectedUseDenied),
            [0x81, 12] => Ok(Self::EvidenceUnavailable),
            [0x81, 13] => Ok(Self::EvidenceExpired),
            [0x81, 14] => Ok(Self::CapacityExhausted),
            [0x81, 15] => Ok(Self::OperationActive),
            [0x81, 16] => Ok(Self::OutcomeUnknown),
            [0x81, 17] => Ok(Self::ContextClosed),
            [0x81, 18] => Ok(Self::StorageUnavailable),
            [0x81, 19] => Ok(Self::RecordingUnavailable),
            _ => Err(Self::InvalidEncoding),
        }
    }
}
