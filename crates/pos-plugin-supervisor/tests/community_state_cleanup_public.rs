//! Owned adapter State cleanup; independent copies retain their own contents.

use pos_plugin_supervisor::CommunityStateV1;
use zeroize::Zeroize;

#[test]
fn explicit_state_cleanup_clears_schema_and_bytes_without_changing_another_copy() {
    for length in [0, 1, 65_536] {
        let original = CommunityStateV1 {
            schema: [9; 32],
            bytes: vec![6; length],
        };
        let mut private = original.clone();
        private.bytes.reserve(13);
        private.zeroize();
        assert_eq!(private.schema, [0; 32]);
        assert!(private.bytes.is_empty());
        private.zeroize();
        drop(private);
        assert_eq!(original.schema, [9; 32]);
        assert_eq!(original.bytes, vec![6; length]);
    }
}
