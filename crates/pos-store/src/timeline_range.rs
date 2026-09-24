//! Signed Timeline Order range verification against a trusted local store.

use std::collections::{BTreeMap, HashSet};

use pos_core::{
    store::{EventStore, SeqRange},
    CoreError, Event, EventOriginV1, KeyIdentityV1, KeyRoleV1, PublicKey, Seq,
    TimelineEventVerificationV1, TimelineId, TimelineMeta,
};
use pos_crypto::{
    key_roles::verify_committed_timeline_event_v1, signing::verifying_key_from_public_key,
};

/// What the retained signed Events prove about one requested Timeline range.
///
/// These are collection-level claims. They do not replace the per-Event
/// cryptographic results and do not compute an ADR-060 `ReplayClaim`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimelineSignedRangeClaimV1 {
    /// At least one signature, ordering, lineage, or head check failed.
    Rejected,
    /// Every supplied Event is valid and contiguous; no trusted head was supplied.
    ContiguousOnly,
    /// A trusted head covers every position in the explicitly bounded range.
    CompleteBounded,
    /// The range ends at the trusted local Logical Head.
    CompleteThroughHead,
}

/// Independent per-Event cryptographic results and collection-level range claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineSignedRangeReportV1 {
    per_event: Vec<TimelineEventVerificationV1>,
    range_claim: TimelineSignedRangeClaimV1,
}

impl TimelineSignedRangeReportV1 {
    /// Cryptographic result for each supplied Event in its supplied order.
    #[must_use]
    pub fn per_event(&self) -> &[TimelineEventVerificationV1] {
        &self.per_event
    }

    /// Collection-level ordering and completeness claim.
    #[must_use]
    pub const fn range_claim(&self) -> TimelineSignedRangeClaimV1 {
        self.range_claim
    }
}

fn trusted_lineage(
    store: &dyn EventStore,
    timeline: TimelineId,
) -> Result<Option<Vec<TimelineMeta>>, CoreError> {
    let mut lineage = Vec::new();
    let mut seen = HashSet::new();
    let mut current = timeline;
    loop {
        if !seen.insert(current) {
            return Ok(None);
        }
        let Some(found) = store.get_timeline(current)? else {
            return Ok(None);
        };
        if found.id() != current {
            return Ok(None);
        }
        let meta = found.meta;
        let parent = meta.fork_point;
        lineage.push(meta);
        let Some((parent, cut)) = parent else {
            return Ok(Some(lineage));
        };
        if store.logical_head(parent)? < cut {
            return Ok(None);
        }
        current = parent;
    }
}

fn origin_matches_lineage(event: &Event, lineage: &[TimelineMeta]) -> bool {
    let Some(origin) = event.origin else {
        return false;
    };
    if origin.origin_logical_seq != event.seq {
        return false;
    }
    let owner = lineage
        .iter()
        .find(|meta| meta.fork_point.is_none_or(|(_, cut)| event.seq > cut));
    owner.is_some_and(|meta| {
        origin
            == EventOriginV1 {
                origin_timeline_id: meta.id,
                origin_logical_seq: event.seq,
            }
    })
}

fn records_are_contiguous(events: &[Event], range: SeqRange) -> bool {
    let Some(last) = events.last() else {
        return false;
    };
    if range.to.is_some_and(|end| end != last.seq) {
        return false;
    }
    let mut expected = range.from.as_u64().max(1);
    let mut ids = HashSet::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        if event.seq.as_u64() != expected || !ids.insert(event.id) {
            return false;
        }
        if index + 1 < events.len() {
            let Some(next) = expected.checked_add(1) else {
                return false;
            };
            expected = next;
        }
    }
    true
}

/// Verify a supplied signed range against the caller's trusted local store.
///
/// `store` supplies authoritative Timeline/Fork metadata, the exact local
/// records for the requested range, the registry, and the Logical Head. The
/// caller independently selects exact owner/role/epoch public-key anchors.
/// `trusted_head` is optional host-selected head evidence: it must match the
/// store's Logical Head before any completeness claim is made. With no head
/// evidence a valid collection receives only `ContiguousOnly`. A successful
/// claim is scoped to this local store and its observed head; it is not a
/// global or future suffix claim. This function makes no ADR-060 `ReplayClaim`.
///
/// # Errors
/// Returns a store error when trusted metadata or records cannot be read, or
/// `SignatureVerificationFailed` for invalid trust-anchor configuration.
pub fn verify_signed_timeline_range_v1(
    store: &dyn EventStore,
    timeline: TimelineId,
    range: SeqRange,
    events: &[Event],
    trust_anchors: &[(KeyIdentityV1, PublicKey)],
    trusted_head: Option<Seq>,
) -> Result<TimelineSignedRangeReportV1, CoreError> {
    let mut anchors = BTreeMap::new();
    for (identity, key) in trust_anchors {
        if identity.role != KeyRoleV1::TimelineIntegritySigning
            || identity.epoch == 0
            || verifying_key_from_public_key(key).is_err()
            || anchors.insert(*identity, *key).is_some()
        {
            return Err(CoreError::SignatureVerificationFailed);
        }
    }
    let registry = store.load_key_registry()?;
    let per_event = events
        .iter()
        .map(|event| {
            let anchor = event
                .signature_identity
                .and_then(|identity| anchors.get(&identity).map(|key| (identity, *key)));
            verify_committed_timeline_event_v1(event, registry.as_ref(), anchor)
        })
        .collect::<Vec<_>>();
    let mut report = TimelineSignedRangeReportV1 {
        per_event,
        range_claim: TimelineSignedRangeClaimV1::Rejected,
    };
    if !report
        .per_event
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Verified)
        || !records_are_contiguous(events, range)
    {
        return Ok(report);
    }
    let Some(lineage) = trusted_lineage(store, timeline)? else {
        return Ok(report);
    };
    if !events
        .iter()
        .all(|event| origin_matches_lineage(event, &lineage))
        || store.read(timeline, range)? != events
    {
        return Ok(report);
    }
    report.range_claim = if let Some(head) = trusted_head {
        if store.logical_head(timeline)? != head
            || events.last().is_some_and(|event| event.seq > head)
        {
            TimelineSignedRangeClaimV1::Rejected
        } else if events.last().is_some_and(|event| event.seq == head) {
            TimelineSignedRangeClaimV1::CompleteThroughHead
        } else if range.to.is_some() {
            TimelineSignedRangeClaimV1::CompleteBounded
        } else {
            TimelineSignedRangeClaimV1::Rejected
        }
    } else {
        TimelineSignedRangeClaimV1::ContiguousOnly
    };
    Ok(report)
}
