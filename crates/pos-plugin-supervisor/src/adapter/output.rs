//! Mapping a guest's output to pipeline `EventDraft`s (ADR-061 validation order).
//!
//! The host's own validation is the only approval: after the supervisor's
//! validation and this mapping, the registry applies its host-owned type,
//! ownership and output-admission checks to every draft, and the store
//! compares and commits the whole batch. The guest has no `approve` export
//! and the adapter adds no approver of its own.

use pos_core::{CanonicalBytes, EntityId, EventDraft, Hash, Kind};
use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::{EventDraftV1, PluginOutputV1};
use pos_runtime::{DeclaredOutputV1, DirectInputRefV1, StepOutput};
use ulid::Ulid;

use super::Error;

/// Every guest digest as a declared node input, in the guest's order.
fn node_digests(digests: &[[u8; 32]]) -> Vec<DirectInputRefV1> {
    digests
        .iter()
        .map(|digest| DirectInputRefV1::NodeDigest {
            digest: Hash::from_bytes(*digest),
        })
        .collect()
}

/// Map one guest draft to the pipeline's `EventDraft` and its declared inputs.
///
/// An `EventDraft` carries an entity, a type and a payload; the draft's
/// `dependency_digests` become `NodeDigest` inputs declared for that draft
/// only. The registry resolves them at admission, so a digest that names no
/// recorded node fails there, not here. An event type outside the ADR-061 ID
/// grammar is `InvalidGuestOutput`.
///
/// The schema ID is the guest's own table index; the host schema registry
/// validates the payload by event type later.
pub(super) fn map_draft(draft: &EventDraftV1) -> Result<DeclaredOutputV1, Error> {
    if !is_valid_id_v1(&draft.event_type) {
        return Err(Error::InvalidGuestOutput);
    }
    Ok(DeclaredOutputV1 {
        draft: EventDraft::new(
            EntityId::from_ulid(Ulid::from(u128::from_be_bytes(draft.entity_id))),
            Kind::new(draft.event_type.clone()),
            CanonicalBytes::from_vec(draft.canonical_payload.clone()),
        ),
        direct_inputs: node_digests(&draft.dependency_digests),
    })
}

/// Every draft of `output`, mapped in the guest's order.
///
/// All drafts together may carry at most `event_bytes` payload bytes (the
/// effective ADR-061 limit); more is `OutputLimitExceeded`. Nothing is staged
/// by this function; the caller stages only when the whole vector succeeds.
pub(super) fn mapped_drafts(
    output: &PluginOutputV1,
    event_bytes: u64,
) -> Result<Vec<DeclaredOutputV1>, Error> {
    let payload_bytes: u64 = output
        .event_drafts
        .iter()
        .map(|draft| u64::try_from(draft.canonical_payload.len()).unwrap_or(u64::MAX))
        .fold(0, u64::saturating_add);
    if payload_bytes > event_bytes {
        return Err(Error::OutputLimitExceeded);
    }
    output.event_drafts.iter().map(map_draft).collect()
}

/// The whole step output: every mapped draft and, at step level, the guest's
/// consumed dependencies as `NodeDigest` inputs.
///
/// The annotations' own digests are not declared: trace annotations are
/// dropped, and only their count survives, in the receipt.
pub(super) fn mapped_output(
    output: &PluginOutputV1,
    event_bytes: u64,
) -> Result<StepOutput, Error> {
    let drafts = mapped_drafts(output, event_bytes)?;
    let step_inputs = node_digests(&output.consumed_dependencies);
    Ok(StepOutput::declared(step_inputs, drafts))
}
