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

    #[error("storage error: {0}")]
    Storage(String),

    #[error("payload too large: {size} bytes")]
    PayloadTooLarge { size: usize },

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("hash chain broken at seq {seq}")]
    HashChainBroken { seq: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TimelineId;

    #[test]
    fn timeline_not_found_displays() {
        let id = TimelineId::new();
        let e = CoreError::TimelineNotFound(id);
        assert!(e.to_string().contains("timeline not found"));
    }

    #[test]
    fn seq_out_of_range_displays() {
        let e = CoreError::SeqOutOfRange {
            requested: 100,
            head: 50,
        };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains("50"));
    }

    #[test]
    fn fork_beyond_head_displays() {
        let e = CoreError::ForkBeyondHead {
            fork_seq: 99,
            head: 10,
        };
        assert!(e.to_string().contains("99"));
    }

    #[test]
    fn storage_error_displays() {
        let e = CoreError::Storage("disk full".to_owned());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn serialization_error_displays() {
        let e = CoreError::Serialization("bad cbor".to_owned());
        assert!(e.to_string().contains("bad cbor"));
    }

    #[test]
    fn payload_too_large_displays() {
        let e = CoreError::PayloadTooLarge { size: 1024 };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn signature_verification_failed_displays() {
        let e = CoreError::SignatureVerificationFailed;
        assert!(e.to_string().contains("verification failed"));
    }

    #[test]
    fn hash_chain_broken_displays() {
        let e = CoreError::HashChainBroken { seq: 7 };
        assert!(e.to_string().contains('7'));
    }
}
