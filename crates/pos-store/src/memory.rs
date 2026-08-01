//! In-memory `EventStore` for tests and single-process use.
//!
//! Fork is copy-on-write: a child stores only its own events.
//! Reading from a forked child transparently stitches parent[`0..fork_seq`] + child events.
//! Multi-level fork chains are supported: a child of a child walks the chain recursively.

use std::collections::{HashMap, HashSet};

use pos_core::{
    clock::{AdmissionClock, Seq, SystemAdmissionClock, WallTime},
    crypto::Hash,
    error::CoreError,
    event::{Event, EventDraft, Kind},
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionFingerprintV1,
        GeoLocationAdmissionIntentV1, GeoLocationAdmissionLinkV1, GeoLocationAdmissionOutcome,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionSnapshotV1, GeoLocationAdmissionStore,
        GeoLocationReplayEvidenceV1, GeoLocationReplayVerifier,
    },
    hasher::Hasher,
    ids::{EntityId, EventId, TimelineId},
    store::{
        checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, AppendIdentity,
        AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome,
        SeqRange,
    },
    timeline::{Timeline, TimelineMeta},
    GEOGRAPHIC_EVENT_TYPE,
};

#[cfg(test)]
thread_local! {
    /// Test-only evidence that bounded reads inspect only selected Event slots.
    static BOUNDED_EVENTS_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// In-memory event store. Thread-unsafe — intended for single-threaded tests and benchmarks.
pub struct MemoryStore {
    /// Complete state per timeline. Keeping this together makes missing companion state
    /// unrepresentable.
    timelines: HashMap<TimelineId, TimelineState>,
    /// Global `EventId` index for O(1) uniqueness checks.
    event_ids: HashSet<EventId>,
    /// Opaque append identities retained only until their fixed horizon.
    append_identities: HashMap<AppendDedupKey, AppendIdentityRecord>,
    /// Durable-equivalent marker for Timelines containing protected evidence.
    geographic_timelines: HashSet<TimelineId>,
    /// Current removable authorization state for protected geographic admission.
    geographic_admission_fences: HashMap<(TimelineId, EntityId), GeoLocationAdmissionFenceV1>,
    /// Private keyed deduplication records for protected geographic admission.
    geographic_admission_dedup:
        HashMap<GeoLocationAdmissionFingerprintV1, GeographicAdmissionDedupRecord>,
    /// Immutable admission snapshots, retained for the lifetime of their Event.
    geographic_admission_snapshots: HashMap<EventId, GeoLocationAdmissionSnapshotV1>,
    /// Immutable Event-to-snapshot links, uniquely keyed by `(TimelineId, EventId)`.
    geographic_admission_links: HashMap<(TimelineId, EventId), GeoLocationAdmissionLinkV1>,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
}

#[inline(never)]
fn read_event_by_id(
    store: &MemoryStore,
    timeline: TimelineId,
    event_id: EventId,
) -> Result<Option<Event>, CoreError> {
    store
        .ensure_generic_timeline_visibility(timeline)
        .and_then(|()| {
            store
                .timelines
                .get(&timeline)
                .ok_or(CoreError::TimelineNotFound(timeline))
        })
        .map(|state| {
            state
                .events
                .iter()
                .find(|event| event.id == event_id)
                .cloned()
        })
}

#[inline(never)]
fn read_own(
    store: &MemoryStore,
    timeline: TimelineId,
    range: SeqRange,
) -> Result<Vec<Event>, CoreError> {
    store
        .ensure_generic_timeline_visibility(timeline)
        .map(|()| {
            store
                .state(timeline)
                .events
                .iter()
                .filter(|event| {
                    event.seq >= range.from && (range.to.is_none() || range.to >= Some(event.seq))
                })
                .cloned()
                .collect()
        })
}

fn has_child_timeline(timelines: &HashMap<TimelineId, TimelineState>, parent: TimelineId) -> bool {
    for state in timelines.values() {
        let Some((child_parent, _)) = state.timeline.meta.fork_point else {
            continue;
        };
        if child_parent == parent {
            return true;
        }
    }
    false
}

fn mutable_state(
    timelines: &mut HashMap<TimelineId, TimelineState>,
    id: TimelineId,
) -> Result<&mut TimelineState, CoreError> {
    timelines
        .get_mut(&id)
        .ok_or(CoreError::TimelineNotFound(id))
}

fn unbounded_append_outcome(
    outcome: Option<AppendOrDuplicateOutcome>,
) -> Result<AppendOrDuplicateOutcome, CoreError> {
    outcome.ok_or_else(|| {
        CoreError::Storage("unbounded append unexpectedly hit an event limit".to_owned())
    })
}

#[inline(never)]
fn delete_timeline(store: &mut MemoryStore, id: TimelineId) -> Result<(), CoreError> {
    store
        .ensure_generic_timeline_visibility(id)
        .and_then(|()| delete_visible_timeline(store, id))
}

fn delete_visible_timeline(store: &mut MemoryStore, id: TimelineId) -> Result<(), CoreError> {
    if has_child_timeline(&store.timelines, id) {
        return Err(CoreError::Storage(
            "cannot delete timeline that still has forks".to_owned(),
        ));
    }
    store
        .timelines
        .remove(&id)
        .ok_or(CoreError::TimelineNotFound(id))
        .map(|state| {
            let event_ids: HashSet<_> = state.events.iter().map(|event| event.id).collect();
            store
                .event_ids
                .retain(|event_id| !event_ids.contains(event_id));
            let existing_identities = std::mem::take(&mut store.append_identities);
            let mut retained_identities = HashMap::with_capacity(existing_identities.len());
            for (key, record) in existing_identities {
                if !event_ids.contains(&record.event_id) {
                    retained_identities.insert(key, record);
                }
            }
            store.append_identities = retained_identities;
            store.geographic_timelines.remove(&id);
            store
                .geographic_admission_fences
                .retain(|(timeline, _), _| *timeline != id);
            store
                .geographic_admission_dedup
                .retain(|_, record| record.timeline != id);
            store
                .geographic_admission_snapshots
                .retain(|event_id, _| !event_ids.contains(event_id));
            store
                .geographic_admission_links
                .retain(|(timeline, event_id), _| *timeline != id && !event_ids.contains(event_id));
        })
}

#[derive(Clone)]
struct AppendIdentityRecord {
    timeline: TimelineId,
    scope: AppendDedupScope,
    event_id: EventId,
    expires_at: WallTime,
    retained_content: RetainedAppendContent,
}

/// Comparison material retained only with an opaque append identity.
#[derive(Clone)]
struct RetainedAppendContent {
    entity: pos_core::EntityId,
    event_type: pos_core::Kind,
    payload: pos_core::CanonicalBytes,
    causation_id: Option<EventId>,
    correlation_id: Option<pos_core::CorrelationId>,
    schema_version: pos_core::SchemaVersion,
}

struct ForkChain {
    timelines: Vec<TimelineId>,
    fork_seqs: Vec<Seq>,
}

struct TimelineState {
    timeline: Timeline,
    events: Vec<Event>,
    chain_head: Hash,
}

impl TimelineState {
    fn new(timeline: Timeline, chain_head: Hash) -> Self {
        Self {
            timeline,
            events: Vec::new(),
            chain_head,
        }
    }
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    fn with_default_components(hasher: Box<dyn Hasher>) -> Self {
        Self {
            timelines: HashMap::new(),
            event_ids: HashSet::new(),
            append_identities: HashMap::new(),
            geographic_timelines: HashSet::new(),
            geographic_admission_fences: HashMap::new(),
            geographic_admission_dedup: HashMap::new(),
            geographic_admission_snapshots: HashMap::new(),
            geographic_admission_links: HashMap::new(),
            hasher,
            clock: Box::new(SystemAdmissionClock),
        }
    }

    #[must_use]
    pub fn with_hasher(hasher: Box<dyn Hasher>) -> Self {
        Self::with_default_components(hasher)
    }

    /// Construct a store with a deterministic or host-provided admission clock.
    #[must_use]
    pub fn with_clock(clock: Box<dyn AdmissionClock>) -> Self {
        let mut store = Self::new();
        store.clock = clock;
        store
    }

    fn append_or_duplicate_with_limit(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        crate::ensure_non_geographic_draft(draft, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                self.append_or_duplicate_with_limit_visible(
                    timeline,
                    identity,
                    admitted_at,
                    draft,
                    max_owned_events,
                )
            })
    }

    fn append_or_duplicate_with_limit_visible(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        if let Some(record) = self.append_identities.get(&identity.dedup_key) {
            if record.expires_at > admitted_at {
                if record.timeline != timeline {
                    return Ok(Some(AppendOrDuplicateOutcome::Conflict));
                }
                return Ok(Some(
                    if Self::retained_content_matches(&record.retained_content, draft) {
                        AppendOrDuplicateOutcome::Duplicate {
                            event_id: record.event_id,
                        }
                    } else {
                        AppendOrDuplicateOutcome::Conflict
                    },
                ));
            }
        }
        if max_owned_events.is_some_and(|maximum| {
            self.timelines
                .get(&timeline)
                .is_some_and(|state| state.timeline.head.as_u64() >= maximum)
        }) {
            return Ok(None);
        }
        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        let event = {
            let (timelines, event_ids, hasher) =
                (&mut self.timelines, &mut self.event_ids, &self.hasher);
            mutable_state(timelines, timeline).map(|state| {
                let event = Self::append_one_to_state(state, draft, hasher.as_ref());
                event_ids.insert(event.id);
                event
            })
        };
        event.map(|event| {
            self.append_identities.insert(
                identity.dedup_key,
                AppendIdentityRecord {
                    timeline,
                    scope: identity.scope,
                    event_id: event.id,
                    expires_at,
                    retained_content: Self::retained_content(&event),
                },
            );
            Some(AppendOrDuplicateOutcome::Appended(Box::new(event)))
        })
    }

    fn timeline(&self, id: TimelineId) -> Result<&Timeline, CoreError> {
        match self.timelines.get(&id) {
            Some(state) => Ok(&state.timeline),
            None => Err(CoreError::TimelineNotFound(id)),
        }
    }

    /// Borrow complete state after the caller has validated the Timeline id.
    fn state(&self, id: TimelineId) -> &TimelineState {
        &self.timelines[&id]
    }

    /// Mutably borrow complete state after the caller has validated the Timeline id.
    fn state_mut(&mut self, id: TimelineId) -> Result<&mut TimelineState, CoreError> {
        mutable_state(&mut self.timelines, id)
    }

    fn append_one_to_state(
        state: &mut TimelineState,
        draft: &EventDraft,
        hasher: &dyn Hasher,
    ) -> Event {
        let seq = state.timeline.head.next();
        let event_id = EventId::new();
        let id_bytes = event_id.to_string();
        let payload_hash = hasher.hash_payload(&draft.payload);
        state.chain_head =
            hasher.hash_event(&state.chain_head, id_bytes.as_bytes(), &draft.payload);
        state.timeline.head = seq;
        let event = Event {
            id: event_id,
            entity: draft.entity,
            event_type: draft.event_type.clone(),
            payload: draft.payload.clone(),
            wall_time: draft.wall_time.unwrap_or_else(WallTime::now),
            seq,
            causation_id: draft.causation_id,
            correlation_id: draft.correlation_id,
            schema_version: draft.schema_version,
            signature: None,
            payload_hash,
        };
        state.events.push(event.clone());
        event
    }

    fn chain_head(&self, id: TimelineId) -> Hash {
        self.state(id).chain_head
    }

    fn retained_content_matches(content: &RetainedAppendContent, draft: &EventDraft) -> bool {
        content.entity == draft.entity
            && content.event_type == draft.event_type
            && content.payload == draft.payload
            && content.causation_id == draft.causation_id
            && content.correlation_id == draft.correlation_id
            && content.schema_version == draft.schema_version
    }

    fn retained_content(event: &Event) -> RetainedAppendContent {
        RetainedAppendContent {
            entity: event.entity,
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            causation_id: event.causation_id,
            correlation_id: event.correlation_id,
            schema_version: event.schema_version,
        }
    }

    /// Collect all events for a timeline, walking the fork chain.
    /// Returns events sorted by seq, stitching parent[`0..fork_seq`] + child events.
    fn collect_events_in_range(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
    ) -> Result<Vec<Event>, CoreError> {
        // Collect the chain of timelines from root to this one
        let chain = self.fork_chain(timeline_id)?;

        // Build the full logical event sequence
        chain
            .timelines
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut all, (i, tid)| {
                self.timeline(*tid).map(|_| {
                    let state = self.state(*tid);
                    let events = &state.events;
                    if let Some(&fork_seq) = chain.fork_seqs.get(i) {
                        all.extend(events.iter().filter(|e| e.seq <= fork_seq).cloned());
                        all
                    } else {
                        all.extend(events.iter().cloned());
                        all
                    }
                })
            })
            .map(|all| crate::stitch::renumber_and_filter(all, range))
    }

    /// Select a logical page without cloning Events outside the requested range.
    fn collect_events_in_range_bounded(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        let chain = self.fork_chain_bounded(timeline_id, bounds.max_fork_depth())?;
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        let mut logical_offset = 0_u64;
        let mut remaining = bounds.max_events();
        let mut selected = Vec::new();

        for (index, timeline) in chain.iter().enumerate() {
            let state = self.state(*timeline);
            let events = &state.events;
            // `fork_chain_bounded` has already verified every Timeline in this chain.
            let head = state.timeline.head.as_u64();
            let event_count = u64::try_from(events.len()).unwrap_or(u64::MAX);
            let boundary_is_valid = if events.is_empty() {
                head == 0
            } else {
                head == event_count
                    && events[0].seq == Seq::from_u64(1)
                    && events[events.len() - 1].seq == Seq::from_u64(event_count)
            };
            if !boundary_is_valid {
                return Err(CoreError::Storage(format!(
                    "timeline {timeline} violates the contiguous Event sequence invariant"
                )));
            }
            let fork_cap = chain.get(index + 1).map(|child| {
                // A successor appears in the chain only when its Fork metadata
                // names this Timeline, as verified by `fork_chain_bounded`.
                self.timelines[child]
                    .timeline
                    .meta
                    .fork_point
                    .map(|(_, seq)| seq)
            });
            let fork_cap = fork_cap.flatten();
            if fork_cap.is_some_and(|cap| cap.as_u64() > event_count) {
                return Err(CoreError::Storage(format!(
                    "Fork point exceeds parent Event head for timeline {timeline}"
                )));
            }
            let segment_len = fork_cap.map_or(event_count, Seq::as_u64);
            if let Some(plan) =
                crate::stitch::plan_page(logical_offset, segment_len, from, to, remaining)
            {
                let raw_start = plan.raw_start;
                let take = plan.take;
                let start_index = usize::try_from(raw_start - 1).unwrap_or(usize::MAX);
                let end_index = start_index.saturating_add(take);
                let slice = &events[start_index..end_index];

                for (offset, event) in slice.iter().enumerate() {
                    #[cfg(test)]
                    BOUNDED_EVENTS_EXAMINED.with(|count| count.set(count.get().saturating_add(1)));
                    let raw_seq =
                        raw_start.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
                    if event.seq != Seq::from_u64(raw_seq) {
                        return Err(CoreError::Storage(format!(
                            "timeline {timeline} violates the contiguous Event sequence invariant"
                        )));
                    }
                    let payload_size = event.payload.as_slice().len();
                    if payload_size > bounds.max_payload_bytes() {
                        return Err(CoreError::PayloadTooLarge { size: payload_size });
                    }
                    let event_type_size = event.event_type.as_str().len();
                    if event_type_size > bounds.max_event_type_bytes() {
                        return Err(CoreError::EventMetadataTooLarge {
                            field: "event_type",
                            size: event_type_size,
                        });
                    }
                    let mut event = event.clone();
                    event.seq = Seq::from_u64(logical_offset.saturating_add(raw_seq));
                    selected.push(event);
                }
                remaining -= take;
            }
            logical_offset = logical_offset.saturating_add(segment_len);
            if remaining == 0 || logical_offset >= to {
                break;
            }
        }
        Ok(selected)
    }

    /// Walk the fork chain from `timeline_id` back to the root, returning [root, ..., `timeline_id`].
    fn fork_chain(&self, timeline_id: TimelineId) -> Result<ForkChain, CoreError> {
        let mut chain = Vec::new();
        let mut fork_seqs = Vec::new();
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        loop {
            if !visited.insert(current) {
                return Err(CoreError::Storage(format!(
                    "fork ancestry contains a cycle at timeline {current}"
                )));
            }
            let meta = self.timeline(current)?;
            chain.push(current);
            match meta.meta.fork_point {
                Some((parent, fork_seq)) => {
                    fork_seqs.push(fork_seq);
                    current = parent;
                }
                None => break,
            }
        }
        chain.reverse();
        fork_seqs.reverse();
        Ok(ForkChain {
            timelines: chain,
            fork_seqs,
        })
    }

    /// Walk at most `max_depth` parent links before returning the chain.
    fn fork_chain_bounded(
        &self,
        timeline_id: TimelineId,
        max_depth: usize,
    ) -> Result<Vec<TimelineId>, CoreError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        let mut depth = 0_usize;
        loop {
            if !visited.insert(current) {
                return Err(CoreError::Storage(format!(
                    "fork ancestry contains a cycle at timeline {current}"
                )));
            }
            let Some(state) = self.timelines.get(&current) else {
                return Err(CoreError::TimelineNotFound(current));
            };
            chain.push(current);
            match state.timeline.meta.fork_point {
                Some((parent, _)) => {
                    let next_depth = depth.saturating_add(1);
                    if next_depth > max_depth {
                        return Err(CoreError::ForkDepthTooLarge { depth: next_depth });
                    }
                    depth = next_depth;
                    current = parent;
                }
                None => break,
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn timeline_contains_geographic_evidence(
        &self,
        timeline: TimelineId,
    ) -> Result<bool, CoreError> {
        self.timeline(timeline)?;
        Ok(self.geographic_timelines.contains(&timeline))
    }

    fn ensure_generic_timeline_visibility(&self, timeline: TimelineId) -> Result<(), CoreError> {
        crate::ensure_generic_timeline_visibility(
            self.timeline_contains_geographic_evidence(timeline),
            timeline,
        )
    }

    fn fork_visible_timeline(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
        let parent_tl = &self.state(parent).timeline;
        if at_seq > parent_tl.head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: parent_tl.head.as_u64(),
            });
        }

        let meta = TimelineMeta::forked_from(parent, at_seq, name);
        let child = Timeline::new(meta);
        let fork_hash = self.compute_chain_hash_at(parent, at_seq)?;
        self.timelines
            .insert(child.id(), TimelineState::new(child.clone(), fork_hash));
        Ok(child)
    }
}

#[derive(Clone, Copy)]
struct GeographicAdmissionDedupRecord {
    timeline: TimelineId,
    intent: GeoLocationAdmissionIntentV1,
    event_id: EventId,
    expires_at: WallTime,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::with_default_components(Box::new(pos_crypto::chain::Blake3Hasher))
    }
}

impl GeoLocationAdmissionAdmin for MemoryStore {
    fn set_geo_location_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.timeline(timeline)?;
        self.geographic_admission_fences
            .insert((timeline, entity), fence);
        Ok(())
    }
}

impl GeoLocationAdmissionStore for MemoryStore {
    fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, CoreError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let admitted_at = self.clock.now()?;
        let permits_request = |store: &Self| {
            store
                .geographic_admission_fences
                .get(&(timeline, entity))
                .is_some_and(|fence| fence.permits(&request))
        };

        if !permits_request(self) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }

        if let Some(record) = self
            .geographic_admission_dedup
            .get(&request.fingerprint())
            .copied()
            .filter(|record| record.expires_at > admitted_at)
        {
            if !permits_request(self) {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            }
            return Ok(GeoLocationAdmissionOutcome::classify_retained_intent(
                request.intent(),
                record.intent,
                record.event_id,
            ));
        }

        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        if !permits_request(self) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }

        let draft = EventDraft::new(
            entity,
            Kind::new(GEOGRAPHIC_EVENT_TYPE),
            request.payload().clone(),
        )
        .with_wall_time(admitted_at);
        let event = {
            let (timelines, event_ids, hasher) =
                (&mut self.timelines, &mut self.event_ids, &self.hasher);
            mutable_state(timelines, timeline).map(|state| {
                let event = Self::append_one_to_state(state, &draft, hasher.as_ref());
                event_ids.insert(event.id);
                event
            })?
        };
        let snapshot = request.snapshot().clone();
        let link =
            GeoLocationAdmissionLinkV1::for_snapshot(timeline, event.id, event.seq, &snapshot);
        let snapshot_hash = self.hasher.hash_payload(link.snapshot_cbor());
        let link = link.with_snapshot_hash(snapshot_hash);

        self.geographic_timelines.insert(timeline);
        self.geographic_admission_snapshots
            .insert(event.id, snapshot);
        self.geographic_admission_links
            .insert((timeline, event.id), link);
        self.geographic_admission_dedup.insert(
            request.fingerprint(),
            GeographicAdmissionDedupRecord {
                timeline,
                intent: request.intent(),
                event_id: event.id,
                expires_at,
            },
        );
        Ok(GeoLocationAdmissionOutcome::accepted(event.id, event.seq))
    }
}

impl GeoLocationReplayVerifier for MemoryStore {
    fn verify_v1_event_snapshot_link(
        &self,
        evidence: GeoLocationReplayEvidenceV1,
    ) -> Result<(), CoreError> {
        let validation_failure = || Err(CoreError::GeographicAdmissionValidationFailed);
        let event = self.timelines.get(&evidence.timeline()).and_then(|state| {
            state
                .events
                .iter()
                .find(|event| event.id == evidence.event_id())
        });
        let Some(event) = event else {
            return validation_failure();
        };
        if event.seq != evidence.event_seq()
            || event.event_type.as_str() != GEOGRAPHIC_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || event.payload_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return validation_failure();
        }
        let Some(snapshot) = self
            .geographic_admission_snapshots
            .get(&evidence.event_id())
        else {
            return validation_failure();
        };
        if snapshot.timeline() != evidence.timeline() || snapshot.entity() != event.entity {
            return validation_failure();
        }
        let Some(link) = self
            .geographic_admission_links
            .get(&(evidence.timeline(), evidence.event_id()))
        else {
            return validation_failure();
        };
        if link
            .validate_for(
                snapshot,
                evidence.timeline(),
                evidence.event_id(),
                evidence.event_seq(),
            )
            .is_err()
            || link.snapshot_hash() != evidence.snapshot_hash()
            || self.hasher.hash_payload(link.snapshot_cbor()) != link.snapshot_hash()
        {
            return validation_failure();
        }
        Ok(())
    }
}

impl EventStore for MemoryStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        let meta = TimelineMeta::root(name);
        let timeline = Timeline::new(meta);
        self.timelines.insert(
            timeline.id(),
            TimelineState::new(timeline.clone(), self.hasher.genesis_hash()),
        );
        Ok(timeline)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        crate::ensure_non_geographic_drafts(drafts, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                let committed = {
                    let (timelines, hasher) = (&mut self.timelines, &self.hasher);
                    mutable_state(timelines, timeline).map(|state| {
                        drafts
                            .iter()
                            .map(|draft| Self::append_one_to_state(state, draft, hasher.as_ref()))
                            .collect::<Vec<_>>()
                    })
                };
                committed.inspect(|events| {
                    self.event_ids.extend(events.iter().map(|event| event.id));
                })
            })
    }

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.append_or_duplicate_with_limit(timeline, identity, admitted_at, &draft, None)
            .and_then(unbounded_append_outcome)
    }

    fn purge_expired_append_identities(&mut self, now: WallTime) -> Result<usize, CoreError> {
        let before = self.append_identities.len();
        self.append_identities
            .retain(|_, record| record.expires_at > now);
        Ok(before.saturating_sub(self.append_identities.len()))
    }

    fn append_intent_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.append_or_duplicate(timeline, identity, admitted_at, draft)
    }

    fn append_intent_or_duplicate_bounded(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        max_owned_events: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.append_or_duplicate_with_limit(
            timeline,
            identity,
            admitted_at,
            &draft,
            Some(max_owned_events),
        )
    }

    fn read_event_by_id(
        &self,
        timeline: TimelineId,
        event_id: EventId,
    ) -> Result<Option<Event>, CoreError> {
        read_event_by_id(self, timeline, event_id)
    }

    fn purge_expired_append_identities_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let now = self.clock.now()?;
        let mut expired: Vec<_> = self
            .append_identities
            .iter()
            .filter(|(_, record)| record.expires_at <= now)
            .map(|(key, record)| (record.expires_at, *key))
            .collect();
        expired.sort_unstable_by_key(|(expires_at, key)| (*expires_at, key.as_bytes()));
        let more_may_remain = expired.len() > limit.get();
        let removed = expired.len().min(limit.get());
        for (_, key) in expired.into_iter().take(removed) {
            self.append_identities.remove(&key);
        }
        Ok(PurgeOutcome {
            removed,
            more_may_remain,
        })
    }

    fn remove_append_identities(&mut self, scope: AppendDedupScope) -> Result<usize, CoreError> {
        let before = self.append_identities.len();
        self.append_identities
            .retain(|_, record| record.scope != scope);
        Ok(before.saturating_sub(self.append_identities.len()))
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.collect_events_in_range(timeline, range))
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.collect_events_in_range_bounded(timeline, range, bounds))
    }

    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        read_own(self, timeline, range)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.ensure_generic_timeline_visibility(parent)
            .and_then(|()| self.fork_visible_timeline(parent, at_seq, name))
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        Ok(self
            .timelines
            .values()
            .filter(|state| {
                crate::generic_timeline_is_visible(
                    self.timeline_contains_geographic_evidence(state.timeline.id()),
                )
                .is_ok_and(|visible| visible)
            })
            .map(|state| state.timeline.clone())
            .collect::<Vec<_>>())
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        let stop_after = maximum.saturating_add(1);
        Ok(self
            .timelines
            .values()
            .filter(|state| state.timeline.meta.is_root())
            .filter(|state| {
                crate::generic_timeline_is_visible(
                    self.timeline_contains_geographic_evidence(state.timeline.id()),
                )
                .is_ok_and(|visible| visible)
            })
            .take(stop_after)
            .count())
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        match self.timelines.get(&id) {
            Some(state) => {
                crate::generic_timeline_is_visible(Ok(self.geographic_timelines.contains(&id)))
                    .map(|visible| visible.then(|| state.timeline.clone()))
            }
            None => Ok(None),
        }
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        // Resolve fork parent before duplicate-id check (parity with SqliteStore).
        let chain = if let Some((parent, at_seq)) = meta.fork_point {
            self.ensure_generic_timeline_visibility(parent)
                .and_then(|()| {
                    let parent_tl = &self.state(parent).timeline;
                    if at_seq > parent_tl.head {
                        Err(CoreError::ForkBeyondHead {
                            fork_seq: at_seq.as_u64(),
                            head: parent_tl.head.as_u64(),
                        })
                    } else {
                        self.compute_chain_hash_at(parent, at_seq)
                    }
                })
        } else {
            Ok(self.hasher.genesis_hash())
        };
        chain.and_then(|chain| {
            if self.timelines.contains_key(&meta.id) {
                return Err(CoreError::Storage(format!(
                    "timeline already exists: {}",
                    meta.id
                )));
            }
            let id = meta.id;
            let timeline = Timeline::new(meta);
            self.timelines
                .insert(id, TimelineState::new(timeline.clone(), chain));
            Ok(timeline)
        })
    }

    fn append_committed(
        &mut self,
        timeline: TimelineId,
        events: &[Event],
    ) -> Result<(), CoreError> {
        crate::ensure_non_geographic_events(events, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                if events.is_empty() {
                    return Ok(());
                }

                let mut timeline_state = self.state(timeline).timeline.clone();
                let head = timeline_state.head;
                let ordered = pos_core::store::validate_committed_batch(
                    head,
                    events,
                    &mut |id| self.event_ids.contains(id),
                    &*self.hasher,
                )?;
                let mut new_head = head;
                let mut previous_hash = self.chain_head(timeline);
                for event in &ordered {
                    let id_str = event.id.to_string();
                    previous_hash =
                        self.hasher
                            .hash_event(&previous_hash, id_str.as_bytes(), &event.payload);
                    new_head = event.seq;
                }

                self.event_ids.extend(ordered.iter().map(|event| event.id));
                self.state_mut(timeline).map(|state| {
                    state.events.extend(ordered);
                    timeline_state.head = new_head;
                    state.timeline = timeline_state;
                    state.chain_head = previous_hash;
                })
            })
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        delete_timeline(self, id)
    }

    fn chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.compute_chain_hash_at(timeline, at_seq))
    }

    fn import_committed(
        &mut self,
        meta: TimelineMeta,
        events: &[Event],
    ) -> Result<Timeline, CoreError> {
        pos_core::store::import_committed_with_rollback(self, meta, events)
    }
}

impl MemoryStore {
    /// Compute the hash chain value at a specific seq in a timeline.
    fn compute_chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
        let chain = self.fork_chain(timeline)?;
        let mut hash = self.hasher.genesis_hash();

        for (i, tid) in chain.timelines.iter().enumerate() {
            let events = &self.state(*tid).events;

            // Ancestors: limit to the *child's* fork_seq onto this timeline (matches SQLite /
            // CoW stitch). Target timeline: limit to `at_seq`.
            let limit = if *tid == timeline {
                at_seq
            } else {
                chain.fork_seqs[i]
            };

            for event in events.iter().filter(|e| e.seq <= limit) {
                let id_str = event.id.to_string();
                hash = self
                    .hasher
                    .hash_event(&hash, id_str.as_bytes(), &event.payload);
            }

            if *tid == timeline {
                break;
            }
        }
        Ok(hash)
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestCorruption {
    ForkParent {
        timeline: TimelineId,
        parent: TimelineId,
        fork_seq: Seq,
    },
}

#[cfg(test)]
impl MemoryStore {
    fn test_corrupt(&mut self, corruption: TestCorruption) {
        match corruption {
            TestCorruption::ForkParent {
                timeline,
                parent,
                fork_seq,
            } => {
                self.timelines
                    .get_mut(&timeline)
                    .expect("test corruption targets an existing Timeline")
                    .timeline
                    .meta
                    .fork_point = Some((parent, fork_seq));
            }
        }
    }

    pub(crate) fn test_remove_timeline(&mut self, id: TimelineId) {
        self.timelines.remove(&id);
        self.geographic_timelines.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        geo_admission::{
            GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
            GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
            GeoLocationReplayVerifier,
        },
        ids::{EntityId, EventId},
        store::{SeqRange, TimelineExport},
    };

    fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    struct ErrorClock;

    impl AdmissionClock for ErrorClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Err(CoreError::Storage("clock failed".to_owned()))
        }
    }

    #[test]
    fn lifecycle_clock_errors_and_expiry_overflow_fail_closed() {
        let draft = make_draft(EntityId::new(), b"payload");
        let intent = AppendIntent::new(&draft);
        let mut clock_error = MemoryStore::with_clock(Box::new(ErrorClock));
        let timeline = clock_error.create_timeline("clock-error").unwrap();
        assert!(clock_error
            .append_intent_or_duplicate(timeline.id(), append_identity(1, 1), intent.clone())
            .is_err());
        assert!(clock_error
            .append_intent_or_duplicate_bounded(
                timeline.id(),
                AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash([3; 32]),
                    AppendDedupScope::from_keyed_hash([4; 32]),
                ),
                intent.clone(),
                1,
            )
            .is_err());
        assert!(clock_error
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());

        let mut overflow = MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(
            WallTime::from_micros(u64::MAX),
        )));
        let timeline = overflow.create_timeline("overflow").unwrap();
        assert!(overflow
            .append_intent_or_duplicate(timeline.id(), append_identity(2, 2), intent)
            .is_err());
        drop(timeline);
    }

    #[test]
    fn geographic_admission_keeps_private_sidecars_in_lockstep_with_timeline_lifecycle() {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("protected").unwrap();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
            )
            .unwrap();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 9),
            ([4; 32], [5; 32]),
        ));

        let accepted = store.admit_geo_location(request.clone()).unwrap();
        let event_id = accepted.event_id().unwrap();
        let event = &store.state(timeline.id()).events[0];
        let snapshot = store.geographic_admission_snapshots.get(&event_id).unwrap();
        let link = store
            .geographic_admission_links
            .get(&(timeline.id(), event_id))
            .unwrap();
        assert!(link
            .validate_for(snapshot, timeline.id(), event_id, event.seq)
            .is_ok());
        assert_eq!(store.geographic_admission_dedup.len(), 1);

        assert!(store.admit_geo_location(request).unwrap().is_duplicate());
        assert_eq!(store.geographic_admission_snapshots.len(), 1);
        assert_eq!(store.geographic_admission_links.len(), 1);

        delete_visible_timeline(&mut store, timeline.id()).unwrap();
        assert!(store.geographic_admission_fences.is_empty());
        assert!(store.geographic_admission_dedup.is_empty());
        assert!(store.geographic_admission_snapshots.is_empty());
        assert!(store.geographic_admission_links.is_empty());
    }

    struct ReplayFixture {
        store: MemoryStore,
        timeline: TimelineId,
        entity: EntityId,
        event_id: EventId,
        event_seq: Seq,
        event_hash: Hash,
        snapshot_hash: Hash,
    }

    impl ReplayFixture {
        fn evidence(
            &self,
            event_payload_hash: Hash,
            snapshot_hash: Hash,
        ) -> GeoLocationReplayEvidenceV1 {
            GeoLocationReplayEvidenceV1::new(
                self.timeline,
                self.event_id,
                self.event_seq,
                event_payload_hash,
                snapshot_hash,
            )
        }
    }

    fn replay_fixture() -> ReplayFixture {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("replay-verifier").unwrap();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
            )
            .unwrap();
        let accepted = store
            .admit_geo_location(GeoLocationAdmissionRequestV1::from_input(
                GeoLocationAdmissionInputV1::new(
                    timeline.id(),
                    entity,
                    CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                    7,
                    ([1; 32], 8, [2; 32]),
                    (1, false, 9),
                    ([4; 32], [5; 32]),
                ),
            ))
            .unwrap();
        let event_id = accepted.event_id().unwrap();
        let event_seq = accepted.event_seq().unwrap();
        let event_hash = store.state(timeline.id()).events[0].payload_hash;
        let snapshot_hash = store.hasher.hash_payload(
            store
                .geographic_admission_links
                .get(&(timeline.id(), event_id))
                .unwrap()
                .snapshot_cbor(),
        );
        ReplayFixture {
            store,
            timeline: timeline.id(),
            entity,
            event_id,
            event_seq,
            event_hash,
            snapshot_hash,
        }
    }

    fn assert_replay_validation(result: Result<(), CoreError>) {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("geographic admission validation failed"));
    }

    #[test]
    fn replay_verifier_accepts_only_exact_event_evidence() {
        let fixture = replay_fixture();

        assert!(fixture
            .store
            .verify_v1_event_snapshot_link(
                fixture.evidence(fixture.event_hash, fixture.snapshot_hash,)
            )
            .is_ok());
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, Hash::from_bytes([0; 32])),
        ));
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(Hash::from_bytes([0; 32]), fixture.snapshot_hash),
        ));
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq.next(),
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
    }

    #[test]
    fn replay_verifier_rejects_changed_canonical_link() {
        let mut fixture = replay_fixture();
        let original_link = fixture
            .store
            .geographic_admission_links
            .get(&(fixture.timeline, fixture.event_id))
            .unwrap()
            .clone();
        let altered_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                fixture.timeline,
                fixture.entity,
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                8,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([6; 32], [7; 32]),
            ));
        fixture.store.geographic_admission_links.insert(
            (fixture.timeline, fixture.event_id),
            GeoLocationAdmissionLinkV1::for_snapshot(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq,
                altered_request.snapshot(),
            ),
        );

        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_links
            .insert((fixture.timeline, fixture.event_id), original_link);
    }

    #[test]
    fn replay_verifier_rejects_missing_sidecars_and_non_geographic_event() {
        let mut fixture = replay_fixture();
        let snapshot = fixture
            .store
            .geographic_admission_snapshots
            .remove(&fixture.event_id)
            .unwrap();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, snapshot);
        let link = fixture
            .store
            .geographic_admission_links
            .remove(&(fixture.timeline, fixture.event_id))
            .unwrap();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_links
            .insert((fixture.timeline, fixture.event_id), link);
        fixture.store.state_mut(fixture.timeline).unwrap().events[0].event_type =
            Kind::new("test.event");
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq,
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
    }

    fn append_identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_and_get_timeline() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let got = store.get_timeline(tl.id()).unwrap();
        assert_eq!(got.as_ref().map(Timeline::id), Some(tl.id()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_and_read_events() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts = vec![
            make_draft(entity, b"first"),
            make_draft(entity, b"second"),
            make_draft(entity, b"third"),
        ];
        let committed = store.append(tl.id(), &drafts).unwrap();
        assert_eq!(committed.len(), 3);

        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), b"first");
        assert_eq!(events[1].payload.as_slice(), b"second");
        assert_eq!(events[2].payload.as_slice(), b"third");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_inherited_event_type_before_clone() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("x".repeat(5)),
            CanonicalBytes::from_static(b"x"),
        );
        store.append(root.id(), &[oversized]).unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        let payload_error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(0, 5, usize::MAX, usize::MAX),
            )
            .unwrap_err();
        assert!(matches!(
            payload_error,
            CoreError::PayloadTooLarge { size: 1 }
        ));
        let error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 4, usize::MAX, usize::MAX),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            CoreError::EventMetadataTooLarge {
                field: "event_type",
                size: 5
            }
        ));
        let events = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 5, usize::MAX, usize::MAX),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_enforces_exact_fork_depth_before_chain_growth() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let mut timelines = vec![root];
        for depth in 1..=65 {
            let parent = timelines.last().unwrap();
            let child = store
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .unwrap();
            timelines.push(child);
        }
        let bounds = EventReadBounds::new(1, 1, 64, usize::MAX);

        assert!(store
            .read_bounded(timelines[64].id(), SeqRange::all(), bounds)
            .unwrap()
            .is_empty());
        let error = store
            .read_bounded(timelines[65].id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_seeks_late_across_forks_and_fetches_only_the_page() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<_> = (0..4_096).map(|_| make_draft(entity, b"x")).collect();
        store.append(root.id(), &drafts).unwrap();
        let child = store
            .fork(root.id(), Seq::from_u64(4_096), "child")
            .unwrap();
        store
            .append(
                child.id(),
                &[make_draft(entity, b"y"), make_draft(entity, b"z")],
            )
            .unwrap();
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 4);

        BOUNDED_EVENTS_EXAMINED.with(|count| count.set(0));
        let page = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_095)), bounds)
            .unwrap();
        assert_eq!(
            page.iter()
                .map(|event| event.seq.as_u64())
                .collect::<Vec<_>>(),
            vec![4_095, 4_096, 4_097, 4_098]
        );
        BOUNDED_EVENTS_EXAMINED.with(|count| assert_eq!(count.get(), 4));

        BOUNDED_EVENTS_EXAMINED.with(|count| count.set(0));
        let exhausted = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_098)), bounds)
            .unwrap();
        assert_eq!(exhausted.len(), 1);
        assert_eq!(exhausted[0].seq.as_u64(), 4_098);
        BOUNDED_EVENTS_EXAMINED.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_fails_closed_when_memory_sequence_metadata_is_corrupt() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("corrupt").unwrap();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[make_draft(entity, b"a"), make_draft(entity, b"b")],
            )
            .unwrap();
        store
            .timelines
            .get_mut(&timeline.id())
            .unwrap()
            .events
            .remove(0);

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut interior_store = MemoryStore::new();
        let timeline = interior_store.create_timeline("interior").unwrap();
        interior_store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .unwrap();
        interior_store
            .timelines
            .get_mut(&timeline.id())
            .unwrap()
            .events[1]
            .seq = Seq::from_u64(99);
        let error = interior_store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut fork_store = MemoryStore::new();
        let root = fork_store.create_timeline("root").unwrap();
        let child = fork_store.fork(root.id(), Seq::ZERO, "child").unwrap();
        fork_store
            .timelines
            .get_mut(&child.id())
            .unwrap()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::from_u64(1)));
        let error = fork_store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, usize::MAX, 1, 1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("Fork point exceeds"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_root_count_ignores_many_children_and_caps_at_maximum_plus_one() {
        let mut store = MemoryStore::new();
        let first = store.create_timeline("first").unwrap();
        for index in 0..256 {
            store
                .fork(first.id(), Seq::ZERO, &format!("child-{index}"))
                .unwrap();
        }
        store.create_timeline("second").unwrap();

        assert_eq!(store.root_timeline_count_bounded(0).unwrap(), 1);
        assert_eq!(store.root_timeline_count_bounded(1).unwrap(), 2);
        assert_eq!(store.root_timeline_count_bounded(10).unwrap(), 2);
        assert_eq!(store.root_timeline_count_bounded(usize::MAX).unwrap(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_is_opaque_and_unchanged() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store.append(tl.id(), &[make_draft(entity, &raw)]).unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_is_monotonically_increasing() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..10).map(|i| make_draft(entity, &[i])).collect();
        let committed = store.append(tl.id(), &drafts).unwrap();
        for (i, e) in committed.iter().enumerate() {
            assert_eq!(e.seq.as_u64(), (i + 1) as u64);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_range_filters_correctly() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).unwrap();

        let events = store
            .read(
                tl.id(),
                SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)),
            )
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), &[1u8]);
        assert_eq!(events[2].payload.as_slice(), &[3u8]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_is_copy_on_write_child_events_do_not_affect_parent() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();

        // Append 3 events to parent
        let parent_drafts = vec![
            make_draft(entity, b"p1"),
            make_draft(entity, b"p2"),
            make_draft(entity, b"p3"),
        ];
        store.append(tl.id(), &parent_drafts).unwrap();

        // Fork at seq 2
        let child = store.fork(tl.id(), Seq::from_u64(2), "child").unwrap();

        // Append to child
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();

        // Parent still has only 3 events
        let parent_events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(parent_events.len(), 3);

        // Child sees parent[0..2] + its own events = 3 total
        let child_events = store.read(child.id(), SeqRange::all()).unwrap();
        assert_eq!(child_events.len(), 3);
        assert_eq!(child_events[0].payload.as_slice(), b"p1");
        assert_eq!(child_events[1].payload.as_slice(), b"p2");
        assert_eq!(child_events[2].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_events_after_fork_point_invisible_to_child() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();

        store
            .append(tl.id(), &[make_draft(entity, b"before")])
            .unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").unwrap();

        // Append to parent AFTER fork
        store
            .append(tl.id(), &[make_draft(entity, b"after-fork")])
            .unwrap();

        // Child should NOT see "after-fork"
        let child_events = store.read(child.id(), SeqRange::all()).unwrap();
        assert!(!child_events
            .iter()
            .any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_returns_error() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let result = store.fork(tl.id(), Seq::from_u64(99), "bad-fork");
        assert!(matches!(result, Err(CoreError::ForkBeyondHead { .. })));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_unknown_timeline_returns_error() {
        let store = MemoryStore::new();
        let unknown = TimelineId::new();
        let result = store.read(unknown, SeqRange::all());
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_to_unknown_timeline_returns_error() {
        let mut store = MemoryStore::new();
        let unknown = TimelineId::new();
        let entity = EntityId::new();
        let result = store.append(unknown, &[make_draft(entity, b"x")]);
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_returns_all() {
        let mut store = MemoryStore::new();
        store.create_timeline("a").unwrap();
        store.create_timeline("b").unwrap();
        store.create_timeline("c").unwrap();
        let list = store.list_timelines().unwrap();
        assert_eq!(list.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_is_deterministic() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).unwrap();

        let r1 = store.read(tl.id(), SeqRange::all()).unwrap();
        let r2 = store.read(tl.id(), SeqRange::all()).unwrap();
        let ids1: Vec<_> = r1.iter().map(|e| e.id).collect();
        let ids2: Vec<_> = r2.iter().map(|e| e.id).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_batch_append_returns_empty() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let result = store.append(tl.id(), &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_at_zero_has_empty_parent_events() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"after")])
            .unwrap();
        let child = store.fork(tl.id(), Seq::ZERO, "empty-fork").unwrap();
        let child_events = store.read(child.id(), SeqRange::all()).unwrap();
        assert!(child_events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explicit_wall_time_is_preserved() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(123_456_789);
        let draft = make_draft(entity, b"pinned").with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).unwrap();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn absent_wall_time_yields_nonzero_timestamp() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let draft = make_draft(entity, b"no-wall-time");
        // wall_time is None — store must call WallTime::now(), which is >0 on any real system.
        let committed = store.append(tl.id(), &[draft]).unwrap();
        assert!(committed[0].wall_time.as_micros() > 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_store_default_equals_new() {
        // Exercises MemoryStore::default()
        let store: MemoryStore = MemoryStore::default();
        // A fresh default store has no timelines.
        let list = store.list_timelines().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at for multi-level fork (parent timeline branch).
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();

        // Append 3 events to root.
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .unwrap();

        // Fork root at seq 2 to get child.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").unwrap();

        // Append 2 events to child.
        store
            .append(
                child.id(),
                &[make_draft(entity, b"c1"), make_draft(entity, b"c2")],
            )
            .unwrap();

        // Fork child at seq 1 (its own event c1) to get grandchild.
        let grandchild = store
            .fork(child.id(), Seq::from_u64(1), "grandchild")
            .unwrap();

        // Append to grandchild.
        store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .unwrap();

        // Grandchild logical view: r1, r2 (from root up to fork 2),
        // then c1 (from child up to fork 1), then g1.
        let events = store.read(grandchild.id(), SeqRange::all()).unwrap();
        let payloads: Vec<&[u8]> = events.iter().map(|e| e.payload.as_slice()).collect();
        assert_eq!(payloads, vec![b"r1" as &[u8], b"r2", b"c1", b"g1"]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_unknown_parent_returns_timeline_not_found() {
        let mut store = MemoryStore::new();
        let unknown = TimelineId::new();
        let result = store.fork(unknown, Seq::ZERO, "orphan");
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_when_fork_parent_metadata_removed() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        store.test_remove_timeline(root.id());
        let err = store.read(child.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_ancestor_metadata_removed() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        store.test_remove_timeline(root.id());
        let err = store.fork(child.id(), Seq::ZERO, "grandchild").unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_cyclic_fork_ancestry() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("cycle").unwrap();
        store.test_corrupt(TestCorruption::ForkParent {
            timeline: timeline.id(),
            parent: timeline.id(),
            fork_seq: Seq::ZERO,
        });

        let error = store.read(timeline.id(), SeqRange::all()).unwrap_err();
        assert!(error.to_string().contains("fork ancestry contains a cycle"));
        let bounded_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .unwrap_err();
        assert!(bounded_error
            .to_string()
            .contains("fork ancestry contains a cycle"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_unknown_timeline() {
        let store = MemoryStore::new();
        let bounded_error = store
            .read_bounded(
                TimelineId::new(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .unwrap_err();
        assert!(bounded_error.to_string().contains("timeline not found"));
    }

    #[test]
    fn bounded_chain_rejects_a_missing_ancestor() {
        let mut store = MemoryStore::new();
        let parent = store.create_timeline("parent").unwrap();
        let child = store.fork(parent.id(), Seq::ZERO, "child").unwrap();
        store.test_remove_timeline(parent.id());

        let error = store
            .collect_events_in_range_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("timeline not found: {}", parent.id())));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multiple_forks_from_same_parent_are_independent() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"shared")])
            .unwrap();

        let branch_a = store.fork(tl.id(), Seq::from_u64(1), "a").unwrap();
        let branch_b = store.fork(tl.id(), Seq::from_u64(1), "b").unwrap();

        store
            .append(branch_a.id(), &[make_draft(entity, b"a-only")])
            .unwrap();
        store
            .append(branch_b.id(), &[make_draft(entity, b"b-only")])
            .unwrap();

        let a_events = store.read(branch_a.id(), SeqRange::all()).unwrap();
        let b_events = store.read(branch_b.id(), SeqRange::all()).unwrap();

        assert!(a_events.iter().any(|e| e.payload.as_slice() == b"a-only"));
        assert!(!a_events.iter().any(|e| e.payload.as_slice() == b"b-only"));
        assert!(b_events.iter().any(|e| e.payload.as_slice() == b"b-only"));
        assert!(!b_events.iter().any(|e| e.payload.as_slice() == b"a-only"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_preserves_timeline_and_event_ids() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let tl = src.create_timeline("shared").unwrap();
        let entity = EntityId::new();
        let committed = src
            .append(
                tl.id(),
                &[make_draft(entity, b"one"), make_draft(entity, b"two")],
            )
            .unwrap();
        let export = export_timeline(&src, tl.id()).unwrap();
        let original_tl_id = tl.id();
        let original_event_ids: Vec<_> = committed.iter().map(|e| e.id).collect();

        let mut dst = MemoryStore::new();
        let imported = import_timeline_with_id(&mut dst, export).unwrap();
        assert_eq!(imported.id(), original_tl_id);
        let events = dst.read(original_tl_id, SeqRange::all()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, original_event_ids[0]);
        assert_eq!(events[1].id, original_event_ids[1]);
        assert_eq!(events[0].payload.as_slice(), b"one");
        assert_eq!(events[1].payload.as_slice(), b"two");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_duplicate_and_missing_parent() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let err = store
            .create_timeline_with_meta(root.meta.clone())
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "orphan");
        let err = store.create_timeline_with_meta(orphan).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fork_uses_parent_chain() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .unwrap();
        let child_meta = TimelineMeta {
            id: TimelineId::new(),
            mode: pos_core::timeline::TimelineMode::Historical,
            name: Some("child".to_owned()),
            fork_point: Some((root.id(), Seq::from_u64(1))),
        };
        let child = store.create_timeline_with_meta(child_meta).unwrap();
        assert!(child.meta.fork_point.is_some());
        store.append_committed(child.id(), &[]).unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_is_atomic_on_mid_batch_failure() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let good = store
            .append(tl.id(), &[make_draft(entity, b"ok")])
            .unwrap()
            .remove(0);

        let mut bad = good.clone();
        bad.id = EventId::new();
        bad.seq = Seq::from_u64(2);
        bad.payload = CanonicalBytes::from_vec(b"bad".to_vec());
        bad.payload_hash = pos_core::Hash::from_bytes([9u8; 32]); // mismatch

        let mut later = good.clone();
        later.id = EventId::new();
        later.seq = Seq::from_u64(3);
        later.payload = CanonicalBytes::from_vec(b"later".to_vec());
        later.payload_hash = pos_crypto::chain::hash_payload(&later.payload);

        let err = store.append_committed(tl.id(), &[bad, later]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // No partial apply: still only the originally appended event.
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"ok");
        assert_eq!(
            store.get_timeline(tl.id()).unwrap().unwrap().head,
            Seq::from_u64(1)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_removes_events_and_blocks_with_forks() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();

        let err = store.delete_timeline(root.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        store.delete_timeline(child.id()).unwrap();
        store.delete_timeline(root.id()).unwrap();
        assert!(store.get_timeline(root.id()).unwrap().is_none());
        let err = store.delete_timeline(root.id()).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rolls_back_create_on_append_fail() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let tl = src.create_timeline("shared").unwrap();
        let entity = EntityId::new();
        let mut committed = src.append(tl.id(), &[make_draft(entity, b"one")]).unwrap();
        let export = export_timeline(&src, tl.id()).unwrap();
        // Corrupt payload hash so append_committed fails after create.
        let mut bad_export = export;
        bad_export.events[0].payload_hash = pos_core::Hash::from_bytes([1u8; 32]);

        let mut dst = MemoryStore::new();
        let err = import_timeline_with_id(&mut dst, bad_export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(dst.get_timeline(tl.id()).unwrap().is_none());
        let _ = committed.remove(0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_validates_seq_and_payload_hash() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);

        // Empty committed append is ok.
        store.append_committed(tl.id(), &[]).unwrap();

        // Collision with existing head (not contiguous — expects head+1).
        let err = store
            .append_committed(tl.id(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Missing timeline.
        let err = store
            .append_committed(TimelineId::new(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        // Bad payload hash.
        good.seq = Seq::from_u64(2);
        good.payload_hash = pos_core::Hash::from_bytes([9u8; 32]);
        let err = store
            .append_committed(tl.id(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // Seq gap rejected.
        good.seq = Seq::from_u64(3);
        good.payload_hash = pos_crypto::chain::hash_payload(&good.payload);
        let err = store
            .append_committed(tl.id(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Seq 0 rejected.
        good.seq = Seq::ZERO;
        let err = store.append_committed(tl.id(), &[good]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_event_id() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .unwrap()
            .remove(0);

        let mut dup = first.clone();
        dup.seq = Seq::from_u64(2);
        dup.payload = CanonicalBytes::from_vec(b"b".to_vec());
        dup.payload_hash = pos_crypto::chain::hash_payload(&dup.payload);
        // same EventId as first
        let err = store.append_committed(tl.id(), &[dup]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_id_in_batch() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let id = EventId::new();
        let mk = |seq: u64, payload: &[u8]| {
            let payload = CanonicalBytes::from_vec(payload.to_vec());
            Event {
                id,
                entity,
                event_type: Kind::new("t"),
                payload: payload.clone(),
                wall_time: WallTime::now(),
                seq: Seq::from_u64(seq),
                causation_id: None,
                correlation_id: None,
                schema_version: pos_core::SchemaVersion::V1,
                signature: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            }
        };
        let err = store
            .append_committed(tl.id(), &[mk(1, b"a"), mk(2, b"b")])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    fn generic_committed_geographic_events_are_rejected() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("geo").unwrap();
        let payload = CanonicalBytes::from_vec(b"protected".to_vec());
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("geo.location"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        assert!(store.append_committed(timeline.id(), &[event]).is_err());
        assert!(store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("ordinary.event"),
                    CanonicalBytes::from_vec(b"allowed".to_vec()),
                )],
            )
            .is_ok());
        assert_eq!(store.read(timeline.id(), SeqRange::all()).unwrap().len(), 1);
    }

    #[test]
    fn read_event_by_id_fails_closed_for_unknown_timeline() {
        let store = MemoryStore::new();
        assert!(store
            .read_event_by_id(TimelineId::new(), EventId::new())
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn read_own_helper_returns_matching_event() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("read-own-helper").unwrap();
        store
            .append(
                timeline.id(),
                &[
                    make_draft(EntityId::new(), b"matching-event"),
                    make_draft(EntityId::new(), b"excluded-event"),
                ],
            )
            .unwrap();

        let events = read_own(
            &store,
            timeline.id(),
            SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
        )
        .unwrap();
        assert_eq!(events.len(), 1);

        let all_events = read_own(&store, timeline.id(), SeqRange::all()).unwrap();
        assert_eq!(all_events.len(), 2);
    }

    #[test]
    fn child_reads_do_not_include_parent_events_after_a_fork_point() {
        let mut store = MemoryStore::new();
        let parent = store.create_timeline("lookup-parent").unwrap();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"before-fork")])
            .unwrap();
        let child = store
            .fork(parent.id(), Seq::from_u64(1), "lookup-child")
            .unwrap();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"after-fork")])
            .unwrap();

        assert_eq!(store.read(child.id(), SeqRange::all()).unwrap().len(), 1);
    }

    #[test]
    fn delete_timeline_helper_removes_append_identity() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("delete-helper").unwrap();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"identified-event"));
        store
            .append_intent_or_duplicate(timeline.id(), append_identity(17, 17), intent)
            .unwrap();

        let retained_timeline = store.create_timeline("retained-identity").unwrap();
        let retained = AppendIntent::new(&make_draft(EntityId::new(), b"retained-event"));
        store
            .append_intent_or_duplicate(retained_timeline.id(), append_identity(18, 18), retained)
            .unwrap();

        store
            .fork(retained_timeline.id(), Seq::ZERO, "retained-child")
            .unwrap();

        delete_timeline(&mut store, timeline.id()).unwrap();
        assert_eq!(store.append_identities.len(), 1);
    }

    #[test]
    fn delete_timeline_helper_handles_an_empty_identity_map() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("delete-empty-identities").unwrap();

        delete_timeline(&mut store, timeline.id()).unwrap();

        assert!(store.append_identities.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mutable_state_lookup_rejects_an_unknown_timeline() {
        let mut store = MemoryStore::new();
        assert!(mutable_state(&mut store.timelines, TimelineId::new()).is_err());
        assert!(store.state_mut(TimelineId::new()).is_err());
        assert!(unbounded_append_outcome(None).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_own_fork_roundtrip_preserves_cow() {
        use pos_core::store::{
            export_timeline, export_timeline_own, export_timeline_raw, import_timeline_with_id,
        };

        let mut src = MemoryStore::new();
        let root = src.create_timeline("root").unwrap();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .unwrap();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();

        // Logical export flattens fork meta.
        let logical = export_timeline(&src, child.id()).unwrap();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.events.len(), 2); // parent[..1] + child

        // Own export keeps CoW shape (`_raw` is a legacy alias of `_own`).
        let own = export_timeline_own(&src, child.id()).unwrap();
        let raw_alias = export_timeline_raw(&src, child.id()).unwrap();
        assert_eq!(own.timeline.id(), raw_alias.timeline.id());
        assert_eq!(own.events.len(), raw_alias.events.len());
        assert_eq!(own.parent_fork_hash, raw_alias.parent_fork_hash);
        assert_eq!(
            own.timeline.meta.fork_point,
            Some((root.id(), Seq::from_u64(1)))
        );
        assert_eq!(own.events.len(), 1);
        assert_eq!(own.events[0].payload.as_slice(), b"c1");

        let mut dst = MemoryStore::new();
        let parent_export = export_timeline_own(&src, root.id()).unwrap();
        import_timeline_with_id(&mut dst, parent_export).unwrap();
        let imported = import_timeline_with_id(&mut dst, own).unwrap();
        assert_eq!(imported.id(), child.id());
        assert!(imported.meta.fork_point.is_some());
        let stitched = dst.read(child.id(), SeqRange::all()).unwrap();
        assert_eq!(stitched.len(), 2);
        assert_eq!(stitched[0].payload.as_slice(), b"p1");
        assert_eq!(stitched[1].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_skips_parent_events() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();
        let own = store.read_own(child.id(), SeqRange::all()).unwrap();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].payload.as_slice(), b"c1");
        let missing = store
            .read_own(TimelineId::new(), SeqRange::all())
            .unwrap_err();
        assert!(matches!(missing, CoreError::TimelineNotFound(_)));

        let bounded = store
            .read_own(
                child.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
            )
            .unwrap();
        assert_eq!(bounded.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_fork_beyond_head() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .unwrap();
        let mut meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(9), "bad");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).unwrap_err();
        assert!(matches!(err, CoreError::ForkBeyondHead { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_fork_chain_hash_ignores_parent_events_after_fork() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[make_draft(entity, b"r1"), make_draft(entity, b"r2")],
            )
            .unwrap();
        let mid = store.fork(root.id(), Seq::from_u64(1), "mid").unwrap();
        store
            .append(mid.id(), &[make_draft(entity, b"m1")])
            .unwrap();
        // Parent continues after fork — must not affect mid/leaf chain heads.
        store
            .append(root.id(), &[make_draft(entity, b"r3")])
            .unwrap();

        let mut leaf_meta = TimelineMeta::forked_from(mid.id(), Seq::from_u64(1), "leaf");
        leaf_meta.id = TimelineId::new();
        let leaf = store.create_timeline_with_meta(leaf_meta).unwrap();

        // Import-equivalent append on leaf must hash from the CoW snapshot, not root's new tip.
        let payload = CanonicalBytes::from_vec(b"l1".to_vec());
        let ev = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: payload.clone(),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        store.append_committed(leaf.id(), &[ev]).unwrap();
        let stitched = store.read(leaf.id(), SeqRange::all()).unwrap();
        // leaf @ mid:1 → root[..1]=r1 + mid[..1]=m1 + leaf l1; root's post-fork r3 stays invisible.
        assert_eq!(stitched.len(), 3);
        assert_eq!(stitched[0].payload.as_slice(), b"r1");
        assert_eq!(stitched[1].payload.as_slice(), b"m1");
        assert_eq!(stitched[2].payload.as_slice(), b"l1");
        assert!(stitched.iter().all(|e| e.payload.as_slice() != b"r3"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn logical_fork_export_remints_ids_so_import_beside_parent_works() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let root = src.create_timeline("root").unwrap();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .unwrap();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();

        let logical = export_timeline(&src, child.id()).unwrap();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.timeline.head, Seq::from_u64(2));
        let parent_ids: std::collections::HashSet<_> = src
            .read_own(root.id(), SeqRange::all())
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        for e in &logical.events {
            assert!(!parent_ids.contains(&e.id));
        }

        let mut dst = MemoryStore::new();
        import_timeline_with_id(&mut dst, export_timeline(&src, root.id()).unwrap()).unwrap();
        // Flattened child import must not collide with parent EventIds.
        import_timeline_with_id(&mut dst, logical).unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_surfaces_broken_parent_chain() {
        let mut store = MemoryStore::new();
        // Parent row exists but its fork_point points at a missing grandparent.
        let mut broken_meta =
            TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "broken");
        broken_meta.id = TimelineId::new();
        let broken = Timeline::new(broken_meta);
        store.timelines.insert(
            broken.id(),
            TimelineState::new(broken.clone(), pos_crypto::chain::genesis_hash()),
        );

        let mut child_meta = TimelineMeta::forked_from(broken.id(), Seq::ZERO, "child");
        child_meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(child_meta).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_rejects_fork_parent_chain_hash_mismatch() {
        use pos_core::store::{export_timeline_own, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let root = src.create_timeline("root").unwrap();
        let entity = EntityId::new();
        src.append(root.id(), &[make_draft(entity, b"p1")]).unwrap();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();

        let mut dst = MemoryStore::new();
        // Divergent parent with same id but different payload.
        let mut parent_export = export_timeline_own(&src, root.id()).unwrap();
        parent_export.events[0].payload = CanonicalBytes::from_vec(b"OTHER".to_vec());
        parent_export.events[0].payload_hash =
            pos_crypto::chain::hash_payload(&parent_export.events[0].payload);
        import_timeline_with_id(&mut dst, parent_export).unwrap();

        let child_export = export_timeline_own(&src, child.id()).unwrap();
        assert!(child_export.parent_fork_hash.is_some());
        let err = import_timeline_with_id(&mut dst, child_export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("chain hash mismatch")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_rejects_when_chain_hash_at_fails() {
        use pos_core::store::import_timeline_with_id;

        struct HashFailOnImport {
            base: MemoryStore,
        }
        impl EventStore for HashFailOnImport {
            fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
                self.base.create_timeline(name)
            }
            fn append(
                &mut self,
                timeline: TimelineId,
                drafts: &[EventDraft],
            ) -> Result<Vec<Event>, CoreError> {
                self.base.append(timeline, drafts)
            }
            fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
                self.base.read(timeline, range)
            }
            fn read_own(
                &self,
                timeline: TimelineId,
                range: SeqRange,
            ) -> Result<Vec<Event>, CoreError> {
                self.base.read_own(timeline, range)
            }
            fn fork(
                &mut self,
                parent: TimelineId,
                at_seq: Seq,
                name: &str,
            ) -> Result<Timeline, CoreError> {
                self.base.fork(parent, at_seq, name)
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                self.base.list_timelines()
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                self.base.get_timeline(id)
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                self.base.create_timeline_with_meta(meta)
            }
            fn append_committed(
                &mut self,
                timeline: TimelineId,
                events: &[Event],
            ) -> Result<(), CoreError> {
                self.base.append_committed(timeline, events)
            }
            fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
                self.base.delete_timeline(id)
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Err(CoreError::Storage("chain lookup failed".to_owned()))
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                pos_core::store::import_committed_with_rollback(self, meta, events)
            }
        }

        let mut store = HashFailOnImport {
            base: MemoryStore::new(),
        };
        let parent = store.create_timeline("root").unwrap();
        let mut meta = TimelineMeta::forked_from(parent.id(), Seq::ZERO, "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::zero()),
        };
        let err = import_timeline_with_id(&mut store, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("chain lookup")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_hasher_uses_custom_hasher() {
        let mut store = MemoryStore::with_hasher(Box::new(pos_crypto::chain::Blake3Hasher));
        let tl = store.create_timeline("hasher-test").unwrap();
        let entity = EntityId::new();
        let drafts = [make_draft(entity, b"payload")];
        let events = store.append(tl.id(), &drafts).unwrap();
        assert_eq!(events.len(), 1);
        assert!(!events[0].payload_hash.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_boundary_rejects_non_v1_serialized_draft() {
        let draft = make_draft(EntityId::new(), b"payload");
        let mut encoded = serde_json::to_value(draft).unwrap();
        encoded["schema_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<EventDraft>(encoded).is_err());
    }
}
