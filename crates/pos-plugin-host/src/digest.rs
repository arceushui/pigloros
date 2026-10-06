//! The `plugin-output` digest that the host recomputes (ADR-061).
//!
//! ADR-061 makes the host recompute `output-digest` over every prior
//! `plugin-output` field and reject a mismatch, but does not fix the bytes
//! that are hashed. This V1 encoding follows the ADR-061 digest conventions
//! (raw BLAKE3-256, a NUL-terminated ASCII domain, unsigned 64-bit big-endian
//! lengths) and is pending owner confirmation:
//!
//! - the domain `PiglorOS.Plugin.Output.v1\0`;
//! - then fields 0-5 in WIT order, each encoded as follows:
//!   - `list<u8>` (including `digest32.value` and `bounded-text.utf8`):
//!     `u64be(length) || bytes`;
//!   - any other list: `u64be(count)`, then each element;
//!   - a record: its fields in WIT order;
//!   - `u32`: four big-endian bytes.

use crate::contract::PluginOutputV1;

/// The domain separator of the V1 output digest, including its NUL.
pub const PLUGIN_OUTPUT_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Plugin.Output.v1\0";

/// The V1 `output-digest` over fields 0-5 of `output`.
///
/// `output.output_digest` itself is not hashed.
#[must_use]
pub fn plugin_output_digest_v1(output: &PluginOutputV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PLUGIN_OUTPUT_DIGEST_DOMAIN_V1);
    put_bytes(&mut hasher, &output.invocation_id);
    put_count(&mut hasher, output.event_drafts.len());
    for draft in &output.event_drafts {
        hasher.update(&draft.event_schema_id.to_be_bytes());
        put_bytes(&mut hasher, &draft.entity_id);
        put_bytes(&mut hasher, draft.event_type.as_bytes());
        put_bytes(&mut hasher, &draft.canonical_payload);
        put_digests(&mut hasher, &draft.dependency_digests);
    }
    put_bytes(&mut hasher, &output.next_state_schema);
    put_bytes(&mut hasher, &output.next_state_bytes);
    put_count(&mut hasher, output.trace_annotations.len());
    for annotation in &output.trace_annotations {
        hasher.update(&annotation.annotation_schema_id.to_be_bytes());
        put_bytes(&mut hasher, &annotation.canonical_bytes);
        put_digests(&mut hasher, &annotation.dependency_digests);
    }
    put_digests(&mut hasher, &output.consumed_dependencies);
    *hasher.finalize().as_bytes()
}

fn put_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_be_bytes());
}

fn put_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    put_count(hasher, bytes.len());
    hasher.update(bytes);
}

fn put_digests(hasher: &mut blake3::Hasher, digests: &[[u8; 32]]) {
    put_count(hasher, digests.len());
    for digest in digests {
        put_bytes(hasher, digest);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::contract::{EventDraftV1, TraceAnnotationV1};

    fn output() -> PluginOutputV1 {
        PluginOutputV1 {
            invocation_id: [1; 16],
            event_drafts: vec![EventDraftV1 {
                event_schema_id: 0x0102_0304,
                entity_id: [2; 16],
                event_type: "t".to_owned(),
                canonical_payload: vec![3],
                dependency_digests: vec![[4; 32]],
            }],
            next_state_schema: [5; 32],
            next_state_bytes: vec![6, 7],
            trace_annotations: vec![TraceAnnotationV1 {
                annotation_schema_id: 9,
                canonical_bytes: vec![10],
                dependency_digests: Vec::new(),
            }],
            consumed_dependencies: vec![[11; 32]],
            output_digest: [0; 32],
        }
    }

    const fn len(count: u64) -> [u8; 8] {
        count.to_be_bytes()
    }

    #[test]
    fn the_digest_hashes_the_documented_encoding_of_fields_0_to_5() {
        let mut expected = PLUGIN_OUTPUT_DIGEST_DOMAIN_V1.to_vec();
        let parts: [&[u8]; 25] = [
            &len(16),
            &[1; 16],
            &len(1),
            &[1, 2, 3, 4],
            &len(16),
            &[2; 16],
            &len(1),
            b"t",
            &len(1),
            &[3],
            &len(1),
            &len(32),
            &[4; 32],
            &len(32),
            &[5; 32],
            &len(2),
            &[6, 7],
            &len(1),
            &[0, 0, 0, 9],
            &len(1),
            &[10],
            &len(0),
            &len(1),
            &len(32),
            &[11; 32],
        ];
        for part in parts {
            expected.extend_from_slice(part);
        }
        let digest = plugin_output_digest_v1(&output());
        assert_eq!(digest, *blake3::hash(&expected).as_bytes());
        let mut moved = output();
        moved.output_digest = [0xff; 32];
        assert_eq!(plugin_output_digest_v1(&moved), digest);
    }
}
