//! Mapping a guest's output to pipeline `EventDraft`s (ADR-061 validation order).
//!
//! The host's own validation is the only approval: after the supervisor's
//! validation and this mapping, the registry applies its host-owned type,
//! ownership and output-admission checks to every draft, and the store
//! compares and commits the whole batch. The guest has no `approve` export
//! and the adapter adds no approver of its own.

use pos_core::{CanonicalBytes, EntityId, EventDraft, Kind};
use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::{CommunityPluginHostErrorV1, EventDraftV1, PluginOutputV1};
use ulid::Ulid;

type Error = CommunityPluginHostErrorV1;

/// Map one guest draft to the pipeline's `EventDraft`.
///
/// An `EventDraft` carries an entity, a type and a payload. A guest draft
/// that cannot map is refused with a closed error:
/// - an event type outside the ADR-061 ID grammar is `InvalidGuestOutput`;
/// - dependency digests have no `EventDraft` field to commit them in, so a
///   draft that declares any is `UnsupportedSchema`, which keeps this
///   limitation distinct from a malformed output.
///
/// The schema ID is the guest's own table index; the host schema registry
/// validates the payload by event type later.
pub(super) fn map_draft(draft: &EventDraftV1) -> Result<EventDraft, Error> {
    if !is_valid_id_v1(&draft.event_type) {
        return Err(Error::InvalidGuestOutput);
    }
    if !draft.dependency_digests.is_empty() {
        return Err(Error::UnsupportedSchema);
    }
    Ok(EventDraft::new(
        EntityId::from_ulid(Ulid::from(u128::from_be_bytes(draft.entity_id))),
        Kind::new(draft.event_type.clone()),
        CanonicalBytes::from_vec(draft.canonical_payload.clone()),
    ))
}

/// Every draft of `output`, mapped in the guest's order.
///
/// All drafts together may carry at most `event_bytes` payload bytes (the
/// effective ADR-061 limit); more is `OutputLimitExceeded`. Nothing is staged
/// by this function; the caller stages only when the whole vector succeeds.
pub(super) fn mapped_drafts(
    output: &PluginOutputV1,
    event_bytes: u64,
) -> Result<Vec<EventDraft>, Error> {
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
