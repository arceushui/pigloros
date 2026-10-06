//! Canonical ABI values and host values shared by the unit tests.

use pos_runtime::community_plugin_host::{
    ArtifactRefV1, PluginInvocationV1, TimelinePositionV1, MAX_OBSERVATION_BYTES_V1,
    MAX_STATE_BYTES_V1,
};
use wasmtime::component::Val;

use crate::host_v1::byte_list;

pub(crate) use crate::lower::record;

/// The artifact reference every test invocation uses.
pub(crate) const ARTIFACT: ArtifactRefV1 = ArtifactRefV1 {
    schema_id: 1,
    byte_length: 0,
    digest: [0; 32],
};

/// A `digest32` value of any length.
pub(crate) fn digest_val(bytes: &[u8]) -> Val {
    record(vec![("value", byte_list(bytes))])
}

/// A `list<digest32>` value.
pub(crate) fn digests_val(digests: &[[u8; 32]]) -> Val {
    Val::List(digests.iter().map(|digest| digest_val(digest)).collect())
}

/// A `bounded-text` value.
pub(crate) fn text_val(text: &str) -> Val {
    record(vec![("utf8", byte_list(text.as_bytes()))])
}

/// A 32-byte digest whose first eight bytes are `index`, big-endian.
pub(crate) fn numbered_digest(index: usize) -> [u8; 32] {
    let mut digest = [0; 32];
    digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
    digest
}

/// An invocation at its WIT bounds.
pub(crate) fn invocation() -> PluginInvocationV1 {
    PluginInvocationV1 {
        invocation_id: [1; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [2; 16],
            seq: 3,
            tick: 4,
            scheduler_position: 5,
        },
        output_base_ordinal: 6,
        principal_ref: ARTIFACT,
        authorization_decision: ARTIFACT,
        observation_snapshot: ARTIFACT,
        observation_bytes: vec![0; MAX_OBSERVATION_BYTES_V1],
        prior_state_schema: [7; 32],
        prior_state_bytes: vec![0; MAX_STATE_BYTES_V1],
        execution_profile_digest: [8; 32],
        trust_policy_snapshot_digest: [9; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [10; 32],
        provenance_root: [11; 32],
    }
}
