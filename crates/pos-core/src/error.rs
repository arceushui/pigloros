use thiserror::Error;

use crate::ids::TimelineId;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("timeline not found: {0}")]
    TimelineNotFound(TimelineId),

    #[error("seq out of range: requested {requested}, head is {head}")]
    SeqOutOfRange { requested: u64, head: u64 },

    #[error("fork point seq {fork_seq} is beyond timeline head {head}")]
    ForkBeyondHead { fork_seq: u64, head: u64 },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("monotonic ULID generator overflow")]
    IdGenerationOverflow,

    #[error("canonical CBOR numeric conversion failed")]
    CanonicalCborNumericConversion,

    #[error("canonical CBOR serialization error: {0}")]
    CanonicalCborSerialization(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("payload too large: {size} bytes")]
    PayloadTooLarge { size: usize },

    #[error("event metadata field {field} too large: {size} bytes")]
    EventMetadataTooLarge { field: &'static str, size: usize },

    #[error("fork depth too large: {depth}")]
    ForkDepthTooLarge { depth: usize },

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("hash chain broken at seq {seq}")]
    HashChainBroken { seq: u64 },

    #[error("geographic admission validation failed")]
    GeographicAdmissionValidationFailed,

    #[error("geographic admission unavailable")]
    GeographicAdmissionUnavailable,

    #[error("geographic admission outcome unknown")]
    GeographicAdmissionOutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TimelineId;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_not_found_displays() {
        let id = TimelineId::new();
        let e = CoreError::TimelineNotFound(id);
        assert!(e.to_string().contains("timeline not found"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_out_of_range_displays() {
        let e = CoreError::SeqOutOfRange {
            requested: 100,
            head: 50,
        };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains("50"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_displays() {
        let e = CoreError::ForkBeyondHead {
            fork_seq: 99,
            head: 10,
        };
        assert!(e.to_string().contains("99"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn storage_error_displays() {
        let e = CoreError::Storage("disk full".to_owned());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn serialization_error_displays() {
        let e = CoreError::Serialization("bad cbor".to_owned());
        assert!(e.to_string().contains("bad cbor"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_generation_overflow_displays() {
        assert!(CoreError::IdGenerationOverflow.to_string().contains("ULID"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_cbor_errors_display() {
        assert!(CoreError::CanonicalCborNumericConversion
            .to_string()
            .contains("numeric"));
        assert!(
            CoreError::CanonicalCborSerialization("writer failed".to_owned())
                .to_string()
                .contains("writer failed")
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_too_large_displays() {
        let e = CoreError::PayloadTooLarge { size: 1024 };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_metadata_too_large_displays() {
        let e = CoreError::EventMetadataTooLarge {
            field: "event_type",
            size: 1024,
        };
        assert!(e.to_string().contains("event_type"));
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_depth_too_large_displays() {
        let e = CoreError::ForkDepthTooLarge { depth: 65 };
        assert!(e.to_string().contains("65"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_verification_failed_displays() {
        let e = CoreError::SignatureVerificationFailed;
        assert!(e.to_string().contains("verification failed"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_chain_broken_displays() {
        let e = CoreError::HashChainBroken { seq: 7 };
        assert!(e.to_string().contains('7'));
    }
}
