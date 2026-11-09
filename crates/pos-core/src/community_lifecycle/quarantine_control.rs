//! Shared artifact references used by complete invocation inputs.

use super::{fixed_bytes, read_head, CommunityLifecycleErrorV1 as Error, Result};
use crate::{encode_bytes, encode_head, CborCursor};

/// Exact `contract-v1.artifact-ref` data for complete prepared-input readers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRefV1 {
    /// Registered schema ID.
    pub schema_id: u32,
    /// Exact artifact length.
    pub byte_length: u64,
    /// BLAKE3-256 artifact digest.
    pub digest: [u8; 32],
}

pub(super) fn encode_artifact_ref(out: &mut Vec<u8>, reference: ArtifactRefV1) {
    out.push(0x83);
    encode_head(out, 0, u64::from(reference.schema_id));
    encode_head(out, 0, reference.byte_length);
    encode_bytes(out, &reference.digest, 2);
}

pub(super) fn read_artifact_ref(cursor: &mut CborCursor<'_>) -> Result<ArtifactRefV1> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0)
            .and_then(|schema| u32::try_from(schema).map_err(|_| Error::BoundsExceeded))
            .and_then(|schema_id| {
                read_head(cursor, 0).and_then(|byte_length| {
                    fixed_bytes(cursor).map(|digest| ArtifactRefV1 {
                        schema_id,
                        byte_length,
                        digest,
                    })
                })
            })
    })
}
