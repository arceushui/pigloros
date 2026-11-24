//! The redaction generation bound is the largest JSON-safe integer (#1407).

use pos_core::REDACTION_GENERATION_MAX_V1;

/// `REDACTION_GENERATION_MAX_V1` is exactly `2^53 - 1`, the
/// `redaction_generation` maximum the Gateway contract declares.
#[test]
fn the_redaction_generation_bound_is_the_largest_json_safe_integer() {
    assert_eq!(REDACTION_GENERATION_MAX_V1, 9_007_199_254_740_991);
}
