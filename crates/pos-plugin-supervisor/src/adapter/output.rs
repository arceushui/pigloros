//! Mapping a guest's output to pipeline `EventDraft`s (ADR-061 validation order).
//!
//! The host's own validation is the only approval: after the supervisor's
//! validation and this mapping, the registry applies its host-owned type,
//! ownership and output-admission checks to every draft, and the store
//! compares and commits the whole batch. The guest has no `approve` export
//! and the adapter adds no approver of its own.

use pos_core::{CanonicalBytes, EntityId, EventDraft, Kind};
use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::{EventDraftV1, PluginOutputV1};
use pos_runtime::{DeclaredOutputV1, StepOutput};
use ulid::Ulid;

use super::Error;

/// A guest digest list must be empty: under the V1 profile no guest is shown a
/// node digest, so any entry is the guest's `UnsupportedSchema` (ADR-061
/// revision 10, 4.1).
const fn refuse_digests(digests: &[[u8; 32]]) -> Result<(), Error> {
    if digests.is_empty() {
        Ok(())
    } else {
        Err(Error::UnsupportedSchema)
    }
}

/// Map one guest draft to the pipeline's `DeclaredOutputV1`, which declares no
/// inputs.
///
/// An `EventDraft` carries an entity, a type and a payload. An event type
/// outside the ADR-061 ID grammar is `InvalidGuestOutput`. Under the V1
/// profile no guest is shown a node digest, so a non-empty `dependency_digests`
/// is the guest's `UnsupportedSchema` (ADR-061 revision 10, 4.1), checked after
/// the event type.
///
/// The schema ID is the guest's own table index; the host schema registry
/// validates the payload by event type later.
pub(super) fn map_draft(draft: &EventDraftV1) -> Result<DeclaredOutputV1, Error> {
    if !is_valid_id_v1(&draft.event_type) {
        return Err(Error::InvalidGuestOutput);
    }
    refuse_digests(&draft.dependency_digests).map(|()| DeclaredOutputV1 {
        draft: EventDraft::new(
            EntityId::from_ulid(Ulid::from(u128::from_be_bytes(draft.entity_id))),
            Kind::new(draft.event_type.clone()),
            CanonicalBytes::from_vec(draft.canonical_payload.clone()),
        ),
        direct_inputs: Vec::new(),
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

/// The whole step output: every mapped draft, declaring no inputs.
///
/// Once every draft passes, a non-empty `consumed_dependencies` is the guest's
/// `UnsupportedSchema` (ADR-061 revision 10, 4.1). The annotations' own digests
/// are not declared: trace annotations are dropped, and only their count
/// survives, in the receipt.
pub(super) fn mapped_output(
    output: &PluginOutputV1,
    event_bytes: u64,
) -> Result<StepOutput, Error> {
    mapped_drafts(output, event_bytes).and_then(|drafts| {
        refuse_digests(&output.consumed_dependencies)
            .map(|()| StepOutput::declared(Vec::new(), drafts))
    })
}
