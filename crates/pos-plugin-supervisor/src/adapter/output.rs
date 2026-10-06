//! Mapping and approving a guest's output (ADR-061 validation order).
//!
//! The order after the supervisor's own validation is: map every draft, then
//! approve every draft with the host-native `ActionApprover`, then stage. The
//! guest has no `approve` export; the approver is the host's own code.

use pos_core::{
    ActionApprover, CanonicalBytes, EntityId, EventDraft, Kind, ProposedAction,
};
use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, EventDraftV1, PluginOutputV1,
};
use ulid::Ulid;

use super::failure::commit_failed;

type Error = CommunityPluginHostErrorV1;

/// The capability the host's approver sees on every community proposal.
pub const APPROVAL_CAPABILITY_V1: &str = "community.plugin.drive";

/// Map one guest draft to the pipeline's `EventDraft`.
///
/// An `EventDraft` carries an entity, a type and a payload. A guest draft
/// that cannot map is `InvalidGuestOutput`: an event type outside the ADR-061
/// ID grammar, or dependency digests, which no `EventDraft` field can carry.
/// The schema ID is the guest's own table index; the host schema registry
/// validates the payload by event type later.
pub(super) fn map_draft(draft: &EventDraftV1) -> Result<EventDraft, Error> {
    if !is_valid_id_v1(&draft.event_type) || !draft.dependency_digests.is_empty() {
        return Err(Error::InvalidGuestOutput);
    }
    Ok(EventDraft::new(
        EntityId::from_ulid(Ulid::from(u128::from_be_bytes(draft.entity_id))),
        Kind::new(draft.event_type.clone()),
        CanonicalBytes::from_vec(draft.canonical_payload.clone()),
    ))
}

/// Approve one mapped draft with the host's `ActionApprover`.
///
/// A typed denial, including a payload above the proposal bound, is the
/// authoritative `AtomicCommitFailed`: the approver's public contract defines
/// a deterministic typed result.
fn approve_draft(approver: &dyn ActionApprover, draft: &EventDraft) -> Result<EventDraft, Error> {
    ProposedAction::try_new(
        draft.event_type.clone(),
        draft.entity,
        draft.payload.clone(),
        Kind::new(APPROVAL_CAPABILITY_V1),
    )
    .and_then(|proposal| approver.approve(&proposal))
    .map_err(|_| commit_failed(AtomicCommitFailureV1::DeterministicTypedResult))
}

/// Every draft of `output`, mapped and then approved, in the guest's order.
///
/// Nothing is staged by this function; the caller stages only when the whole
/// vector succeeds.
pub(super) fn approved_drafts(
    approver: &dyn ActionApprover,
    output: &PluginOutputV1,
) -> Result<Vec<EventDraft>, Error> {
    output
        .event_drafts
        .iter()
        .map(map_draft)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|drafts| {
            drafts
                .iter()
                .map(|draft| approve_draft(approver, draft))
                .collect()
        })
}
