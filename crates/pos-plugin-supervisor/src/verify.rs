//! The supervisor's own checks of a returned guest value.
//!
//! The in-worker engine fully validates every return before it is framed. A
//! worker is not trusted to have done so, so the supervisor re-checks what it
//! can without the Wasmtime runtime. A value that fails is the authoritative
//! `InvalidGuestOutput`.

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, NegotiatedCommunityPluginV1, PluginDescriptorV1,
    PluginInvocationV1, PluginOutputV1, MAX_TRACE_ANNOTATION_BYTES_V1,
};

/// Whether `descriptor` describes `negotiated`.
///
/// The Plugin ID, world, ABI major, declared minors and required features
/// must equal the negotiated release, and the manifest and release digests
/// must be the 32 zero bytes V1 requires.
pub(super) fn verify_descriptor(
    descriptor: &PluginDescriptorV1,
    negotiated: &NegotiatedCommunityPluginV1,
) -> bool {
    let (abi_major, _) = negotiated.abi();
    descriptor.plugin_id == negotiated.plugin_id()
        && descriptor.world == negotiated.world()
        && descriptor.abi_major == abi_major
        && (descriptor.min_abi_minor, descriptor.max_abi_minor)
            == negotiated.declared_minor_range()
        && descriptor.required_features == negotiated.required_features()
        && descriptor.manifest_digest == [0; 32]
        && descriptor.release_digest == [0; 32]
}

/// Whether `output` answers `invocation` within `limits`.
///
/// It must echo the invocation ID, carry the V1 output digest of its own
/// fields, and stay within the effective Event count, the state bytes and the
/// 1 MiB of trace annotation bytes.
pub(super) fn verify_output(
    output: &PluginOutputV1,
    invocation: &PluginInvocationV1,
    limits: &DeterministicBudgetV1,
) -> bool {
    let annotation_bytes: usize = output
        .trace_annotations
        .iter()
        .map(|annotation| annotation.canonical_bytes.len())
        .sum();
    output.invocation_id == invocation.invocation_id
        && output.output_digest == plugin_output_digest_v1(output)
        && output.event_drafts.len() as u64 <= limits.event_count
        && output.next_state_bytes.len() as u64 <= limits.state_bytes
        && annotation_bytes <= MAX_TRACE_ANNOTATION_BYTES_V1
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
