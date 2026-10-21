//! The generation and served-count rules in isolation.

use super::{check_served, next_generation};
use crate::{BridgeError, ProtocolCode, ServedSnapshot, UnavailableCode};

const INTEGRITY: BridgeError = BridgeError::Unavailable(UnavailableCode::AssetIntegrity);
const EXHAUSTED: BridgeError = BridgeError::Unavailable(UnavailableCode::GenerationExhausted);

#[test]
fn the_generation_advances_until_the_last_value_before_the_limit() {
    assert_eq!(next_generation(0), Ok(1));
    assert_eq!(next_generation(1), Ok(2));
    assert_eq!(next_generation(u32::MAX - 2), Ok(u32::MAX - 1));
    assert_eq!(next_generation(u32::MAX - 1), Err(EXHAUSTED));
    assert_eq!(next_generation(u32::MAX), Err(EXHAUSTED));
}

#[test]
fn the_served_count_rule_wants_exactly_one_verified_completion() {
    let served = |count, integrity_ok| ServedSnapshot {
        count,
        integrity_ok,
    };
    assert_eq!(check_served(served(1, true)), Ok(()));
    assert_eq!(check_served(served(0, true)), Err(INTEGRITY));
    assert_eq!(check_served(served(0, false)), Err(INTEGRITY));
    assert_eq!(check_served(served(1, false)), Err(INTEGRITY));
    assert_eq!(check_served(served(2, false)), Err(INTEGRITY));
    assert_eq!(
        check_served(served(2, true)),
        Err(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad))
    );
    assert_eq!(
        check_served(served(u32::MAX, true)),
        Err(BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad))
    );
}
