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
    event::{Event, EventDraft},
    hasher::Hasher,
    ids::{EventId, TimelineId},
    store::{
        checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, AppendIdentity,
        AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome,
        SeqRange,
    },
    timeline::{Timeline, TimelineMeta},
};

#[cfg(test)]
thread_local! {
    /// Test-only evidence that bounded reads inspect only selected Event slots.
    static BOUNDED_EVENTS_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// In-memory event store. Thread-unsafe — intended for single-threaded tests and benchmarks.
pub struct MemoryStore {
    /// Events stored per timeline (only events appended directly to that timeline).
    events: HashMap<TimelineId, Vec<Event>>,
    /// Timeline metadata.
    timelines: HashMap<TimelineId, Timeline>,
    /// Running hash chain head per timeline.
    chain_heads: HashMap<TimelineId, Hash>,
    /// Global `EventId` index for O(1) uniqueness checks.
    event_ids: HashSet<EventId>,
    /// Opaque append identities retained only until their fixed horizon.
    append_identities: HashMap<AppendDedupKey, AppendIdentityRecord>,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
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

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            timelines: HashMap::new(),
            chain_heads: HashMap::new(),
            event_ids: HashSet::new(),
            append_identities: HashMap::new(),
            hasher: Box::new(pos_crypto::chain::Blake3Hasher),
            clock: Box::new(SystemAdmissionClock),
        }
    }

    #[must_use]
    pub fn with_hasher(hasher: Box<dyn Hasher>) -> Self {
        Self {
            events: HashMap::new(),
            timelines: HashMap::new(),
            chain_heads: HashMap::new(),
            event_ids: HashSet::new(),
            append_identities: HashMap::new(),
            hasher,
            clock: Box::new(SystemAdmissionClock),
        }
    }

    /// Construct a store with a deterministic or host-provided admission clock.
    #[must_use]
    pub fn with_clock(clock: Box<dyn AdmissionClock>) -> Self {
        let mut store = Self::new();
        store.clock = clock;
        store
    }

    fn timeline(&self, id: TimelineId) -> Result<&Timeline, CoreError> {
        match self.timelines.get(&id) {
            Some(timeline) => Ok(timeline),
            None => Err(CoreError::TimelineNotFound(id)),
        }
    }

    fn chain_head(&self, id: TimelineId) -> Result<Hash, CoreError> {
        match self.chain_heads.get(&id) {
            Some(hash) => Ok(*hash),
            None => Err(Self::missing_timeline_state(id, "hash-chain head")),
        }
    }

    fn missing_timeline_state(id: TimelineId, state: &str) -> CoreError {
        CoreError::Storage(format!("timeline {id} is missing its {state}"))
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
                    let events = self.events.get(tid).map_or(&[] as &[Event], Vec::as_slice);
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
            let events = self
                .events
                .get(timeline)
                .map_or(&[] as &[Event], Vec::as_slice);
            // `fork_chain_bounded` has already verified every Timeline in this chain.
            let head = self.timelines[timeline].head.as_u64();
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
                self.timelines[child].meta.fork_point.map(|(_, seq)| seq)
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
            let meta = self
                .timelines
                .get(&current)
                .ok_or(CoreError::TimelineNotFound(current))?;
            chain.push(current);
            match meta.meta.fork_point {
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
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore for MemoryStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        let meta = TimelineMeta::root(name);
        let timeline = Timeline::new(meta);
        self.timelines.insert(timeline.id(), timeline.clone());
        self.events.insert(timeline.id(), Vec::new());
        self.chain_heads
            .insert(timeline.id(), self.hasher.genesis_hash());
        Ok(timeline)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        let timeline_state = self.timeline(timeline).cloned();
        let chain_head = self.chain_head(timeline);
        let (mut timeline_state, mut prev_hash) = match (timeline_state, chain_head) {
            (Ok(timeline_state), Ok(chain_head)) => (timeline_state, chain_head),
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        let mut seq = timeline_state.head;

        let mut committed = Vec::with_capacity(drafts.len());

        for draft in drafts {
            seq = seq.next();
            let event_id = EventId::new();
            let id_bytes = event_id.to_string();
            let payload_hash = self.hasher.hash_payload(&draft.payload);
            let chain_hash =
                self.hasher
                    .hash_event(&prev_hash, id_bytes.as_bytes(), &draft.payload);

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

            committed.push(event);
            prev_hash = chain_hash;
        }

        let Some(events) = self.events.get_mut(&timeline) else {
            return Err(Self::missing_timeline_state(timeline, "Event storage"));
        };
        events.extend(committed.iter().cloned());
        self.event_ids
            .extend(committed.iter().map(|event| event.id));

        // Update head and chain hash
        timeline_state.head = seq;
        self.timelines.insert(timeline, timeline_state);
        self.chain_heads.insert(timeline, prev_hash);

        Ok(committed)
    }

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.timeline(timeline)?;
        if let Some(record) = self.append_identities.get(&identity.dedup_key) {
            if record.expires_at > admitted_at {
                if record.timeline != timeline {
                    return Ok(AppendOrDuplicateOutcome::Conflict);
                }
                return if Self::retained_content_matches(&record.retained_content, &draft) {
                    Ok(AppendOrDuplicateOutcome::Duplicate {
                        event_id: record.event_id,
                    })
                } else {
                    Ok(AppendOrDuplicateOutcome::Conflict)
                };
            }
        }

        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        let mut events = self.append(timeline, std::slice::from_ref(&draft))?;
        let Some(event) = events.pop() else {
            return Err(CoreError::Storage(
                "empty append while recording ingress identity".to_owned(),
            ));
        };
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
        Ok(AppendOrDuplicateOutcome::Appended(Box::new(event)))
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
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        self.collect_events_in_range(timeline, range)
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.collect_events_in_range_bounded(timeline, range, bounds)
    }

    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        let events = self
            .events
            .get(&timeline)
            .map_or(&[] as &[Event], Vec::as_slice);
        let filtered: Vec<Event> = events
            .iter()
            .filter(|e| e.seq >= range.from && range.to.is_none_or(|to| e.seq <= to))
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        let parent_tl = self
            .timelines
            .get(&parent)
            .ok_or(CoreError::TimelineNotFound(parent))?;

        if at_seq > parent_tl.head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: parent_tl.head.as_u64(),
            });
        }

        let meta = TimelineMeta::forked_from(parent, at_seq, name);
        let child = Timeline::new(meta);
        self.timelines.insert(child.id(), child.clone());
        self.events.insert(child.id(), Vec::new());

        // Snapshot the hash chain at the fork point: read parent events up to at_seq
        let fork_hash = self.compute_chain_hash_at(parent, at_seq)?;
        self.chain_heads.insert(child.id(), fork_hash);

        Ok(child)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        Ok(self.timelines.values().cloned().collect())
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        let stop_after = maximum.saturating_add(1);
        Ok(self
            .timelines
            .values()
            .filter(|timeline| timeline.meta.is_root())
            .take(stop_after)
            .count())
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        Ok(self.timelines.get(&id).cloned())
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        // Resolve fork parent before duplicate-id check (parity with SqliteStore).
        let chain = if let Some((parent, at_seq)) = meta.fork_point {
            let parent_tl = self
                .timelines
                .get(&parent)
                .ok_or(CoreError::TimelineNotFound(parent))?;
            if at_seq > parent_tl.head {
                return Err(CoreError::ForkBeyondHead {
                    fork_seq: at_seq.as_u64(),
                    head: parent_tl.head.as_u64(),
                });
            }
            self.compute_chain_hash_at(parent, at_seq)?
        } else {
            self.hasher.genesis_hash()
        };
        if self.timelines.contains_key(&meta.id) {
            return Err(CoreError::Storage(format!(
                "timeline already exists: {}",
                meta.id
            )));
        }
        let id = meta.id;
        let timeline = Timeline::new(meta);
        self.timelines.insert(id, timeline.clone());
        self.events.insert(id, Vec::new());
        self.chain_heads.insert(id, chain);
        Ok(timeline)
    }

    fn append_committed(
        &mut self,
        timeline: TimelineId,
        events: &[Event],
    ) -> Result<(), CoreError> {
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        if events.is_empty() {
            return Ok(());
        }

        let mut timeline_state = self.timelines[&timeline].clone();
        let head = timeline_state.head;
        pos_core::store::validate_committed_batch(
            head,
            events,
            &mut |id| self.event_ids.contains(id),
            &*self.hasher,
        )
        .and_then(|ordered| {
            self.chain_head(timeline).and_then(|prev_hash| {
                let Some(stored_events) = self.events.get_mut(&timeline) else {
                    return Err(Self::missing_timeline_state(timeline, "Event storage"));
                };
                let mut new_head = head;
                let mut previous_hash = prev_hash;
                for event in &ordered {
                    let id_str = event.id.to_string();
                    previous_hash =
                        self.hasher
                            .hash_event(&previous_hash, id_str.as_bytes(), &event.payload);
                    new_head = event.seq;
                }

                self.event_ids.extend(ordered.iter().map(|event| event.id));
                stored_events.extend(ordered);
                timeline_state.head = new_head;
                self.timelines.insert(timeline, timeline_state);
                self.chain_heads.insert(timeline, previous_hash);
                Ok(())
            })
        })
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        if !self.timelines.contains_key(&id) {
            return Err(CoreError::TimelineNotFound(id));
        }
        if self
            .timelines
            .values()
            .any(|t| t.meta.fork_point.is_some_and(|(parent, _)| parent == id))
        {
            return Err(CoreError::Storage(
                "cannot delete timeline that still has forks".to_owned(),
            ));
        }
        self.chain_head(id).and_then(|_| {
            let Some(events) = self.events.remove(&id) else {
                return Err(Self::missing_timeline_state(id, "Event storage"));
            };
            let timeline = self.timelines.remove(&id);
            debug_assert!(
                timeline.is_some(),
                "Timeline existence was validated before deletion"
            );
            let event_ids: HashSet<_> = events.iter().map(|event| event.id).collect();
            self.event_ids
                .retain(|event_id| !event_ids.contains(event_id));
            self.append_identities
                .retain(|_, record| !event_ids.contains(&record.event_id));
            self.chain_heads.remove(&id);
            Ok(())
        })
    }

    fn chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
        self.compute_chain_hash_at(timeline, at_seq)
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
            let events = self.events.get(tid).map_or(&[] as &[Event], Vec::as_slice);

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
    MissingChainHead(TimelineId),
    MissingEvents(TimelineId),
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
                    .meta
                    .fork_point = Some((parent, fork_seq));
            }
            TestCorruption::MissingChainHead(timeline) => {
                self.chain_heads.remove(&timeline);
            }
            TestCorruption::MissingEvents(timeline) => {
                self.events.remove(&timeline);
            }
        }
    }

    pub(crate) fn test_remove_timeline(&mut self, id: TimelineId) {
        self.timelines.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
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
        store.events.get_mut(&timeline.id()).unwrap().remove(0);

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
        interior_store.events.get_mut(&timeline.id()).unwrap()[1].seq = Seq::from_u64(99);
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
    fn mutation_rejects_missing_internal_timeline_state_without_partial_delete() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("incomplete").unwrap();
        store.test_corrupt(TestCorruption::MissingChainHead(timeline.id()));

        let append_error = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"event")])
            .unwrap_err();
        assert!(append_error
            .to_string()
            .contains("missing its hash-chain head"));

        let delete_error = store.delete_timeline(timeline.id()).unwrap_err();
        assert!(delete_error
            .to_string()
            .contains("missing its hash-chain head"));
        assert!(store.get_timeline(timeline.id()).unwrap().is_some());

        store
            .chain_heads
            .insert(timeline.id(), pos_crypto::chain::genesis_hash());
        store.test_corrupt(TestCorruption::MissingEvents(timeline.id()));
        let missing_events_error = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"event")])
            .unwrap_err();
        assert!(missing_events_error
            .to_string()
            .contains("missing its Event storage"));
        let delete_error = store.delete_timeline(timeline.id()).unwrap_err();
        assert!(delete_error
            .to_string()
            .contains("missing its Event storage"));
        assert!(store.get_timeline(timeline.id()).unwrap().is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn committed_append_and_bounded_read_reject_missing_timeline_state() {
        let mut source = MemoryStore::new();
        let source_timeline = source.create_timeline("source").unwrap();
        let committed = source
            .append(
                source_timeline.id(),
                &[make_draft(EntityId::new(), b"event")],
            )
            .unwrap();

        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("incomplete").unwrap();
        store.test_corrupt(TestCorruption::MissingEvents(timeline.id()));
        let events_error = store
            .append_committed(timeline.id(), &committed)
            .unwrap_err();
        assert!(events_error
            .to_string()
            .contains("missing its Event storage"));

        store.events.insert(timeline.id(), Vec::new());
        store.test_corrupt(TestCorruption::MissingChainHead(timeline.id()));
        let chain_error = store
            .append_committed(timeline.id(), &committed)
            .unwrap_err();
        assert!(chain_error
            .to_string()
            .contains("missing its hash-chain head"));

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
        store.timelines.insert(broken.id(), broken.clone());
        store.events.insert(broken.id(), Vec::new());
        store
            .chain_heads
            .insert(broken.id(), pos_crypto::chain::genesis_hash());

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
    fn read_upcast_on_memory_store_default_noop() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("upcast-test").unwrap();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"payload")])
            .unwrap();
        let upcasters = pos_core::UpcasterRegistry::new();
        let schema_versions = pos_core::SchemaVersionMap::new();
        let store_ref: &dyn pos_core::EventStore = &store;
        let result = store_ref
            .read_upcast(
                tl.id(),
                pos_core::store::SeqRange::all(),
                &upcasters,
                &schema_versions,
            )
            .unwrap();
        assert!(!result.is_empty());
    }
}
