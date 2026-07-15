//! In-memory `EventStore` for tests and single-process use.
//!
//! Fork is copy-on-write: a child stores only its own events.
//! Reading from a forked child transparently stitches parent[`0..fork_seq`] + child events.
//! Multi-level fork chains are supported: a child of a child walks the chain recursively.

use std::collections::HashMap;

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    error::CoreError,
    event::{Event, EventDraft},
    ids::{EventId, TimelineId},
    store::{EventStore, SeqRange},
    timeline::{Timeline, TimelineMeta},
};
use pos_crypto::chain::{genesis_hash, hash_event};

/// In-memory event store. Thread-unsafe — intended for single-threaded tests and benchmarks.
pub struct MemoryStore {
    /// Events stored per timeline (only events appended directly to that timeline).
    events: HashMap<TimelineId, Vec<Event>>,
    /// Timeline metadata.
    timelines: HashMap<TimelineId, Timeline>,
    /// Running hash chain head per timeline.
    chain_heads: HashMap<TimelineId, Hash>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            timelines: HashMap::new(),
            chain_heads: HashMap::new(),
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
        let mut all: Vec<Event> = Vec::new();
        let mut prev_fork_seq: Option<Seq> = None;

        for (i, tid) in chain.iter().enumerate() {
            let meta = &self.timelines[tid].meta;
            let events = self.events.get(tid).map_or(&[] as &[Event], Vec::as_slice);

            if i + 1 < chain.len() {
                // This is a parent: include up to the fork point of its child
                let child_meta = &self.timelines[&chain[i + 1]].meta;
                let fork_seq = child_meta.fork_point.unwrap().1;
                for e in events.iter().filter(|e| e.seq <= fork_seq) {
                    all.push(e.clone());
                }
                prev_fork_seq = Some(fork_seq);
            } else {
                // This is the leaf timeline: include all its own events
                for e in events {
                    all.push(e.clone());
                }
            }
            let _ = (meta, prev_fork_seq); // suppress unused warnings
        }

        // Sort by logical position (insertion order) rather than raw seq,
        // since child timelines restart seq from 1.
        // Filter by range using the logical seq (position in all).
        let filtered = all
            .into_iter()
            .enumerate()
            .map(|(i, mut e)| {
                // Re-number seq to reflect logical position in the stitched timeline
                e.seq = Seq::from_u64((i + 1) as u64);
                e
            })
            .filter(|e| {
                e.seq >= range.from && range.to.map_or(true, |to| e.seq <= to)
            })
            .collect();
        Ok(filtered)
    }

    /// Walk the fork chain from `timeline_id` back to the root, returning [root, ..., `timeline_id`].
    fn fork_chain(&self, timeline_id: TimelineId) -> Result<Vec<TimelineId>, CoreError> {
        let mut chain = Vec::new();
        let mut current = timeline_id;
        loop {
            let meta = self
                .timelines
                .get(&current)
                .ok_or(CoreError::TimelineNotFound(current))?;
            chain.push(current);
            match meta.meta.fork_point {
                Some((parent, _)) => current = parent,
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
        self.chain_heads.insert(timeline.id(), genesis_hash());
        Ok(timeline)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        let tl = self
            .timelines
            .get_mut(&timeline)
            .ok_or(CoreError::TimelineNotFound(timeline))?;

        let mut seq = tl.head;
        let mut prev_hash = *self
            .chain_heads
            .get(&timeline)
            .unwrap_or(&genesis_hash());

        let events_vec = self.events.entry(timeline).or_default();
        let mut committed = Vec::with_capacity(drafts.len());

        for draft in drafts {
            seq = seq.next();
            let event_id = EventId::new();
            let id_bytes = event_id.to_string();
            let payload_hash = pos_crypto::chain::hash_payload(&draft.payload);
            let chain_hash = hash_event(&prev_hash, id_bytes.as_bytes(), &draft.payload);

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

            events_vec.push(event.clone());
            committed.push(event);
            prev_hash = chain_hash;
        }

        // Update head and chain hash
        self.timelines.get_mut(&timeline).unwrap().head = seq;
        self.chain_heads.insert(timeline, prev_hash);

        Ok(committed)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        self.collect_events_in_range(timeline, range)
    }

    fn fork(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
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

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        Ok(self.timelines.get(&id).cloned())
    }
}

impl MemoryStore {
    /// Compute the hash chain value at a specific seq in a timeline.
    fn compute_chain_hash_at(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<Hash, CoreError> {
        let chain = self.fork_chain(timeline)?;
        let mut hash = genesis_hash();

        for tid in &chain {
            let events = self.events.get(tid).map_or(&[] as &[Event], Vec::as_slice);
            let meta = &self.timelines[tid].meta;

            let limit = if *tid == timeline {
                at_seq
            } else {
                // For parent timelines, use their child's fork point as the limit
                meta.fork_point
                    .map_or(Seq::from_u64(u64::MAX), |(_, s)| s)
            };

            for event in events.iter().filter(|e| e.seq <= limit) {
                let id_str = event.id.to_string();
                hash = hash_event(&hash, id_str.as_bytes(), &event.payload);
            }

            if *tid == timeline {
                break;
            }
        }
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        store::SeqRange,
    };

    fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    #[test]
    fn create_and_get_timeline() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let got = store.get_timeline(tl.id()).unwrap();
        assert_eq!(got.as_ref().map(Timeline::id), Some(tl.id()));
    }

    #[test]
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
    fn payload_is_opaque_and_unchanged() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store
            .append(tl.id(), &[make_draft(entity, &raw)])
            .unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
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
    fn read_range_filters_correctly() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).unwrap();

        let events = store
            .read(tl.id(), SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)))
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), &[1u8]);
        assert_eq!(events[2].payload.as_slice(), &[3u8]);
    }

    #[test]
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
        assert!(!child_events.iter().any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    fn fork_beyond_head_returns_error() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let result = store.fork(tl.id(), Seq::from_u64(99), "bad-fork");
        assert!(matches!(result, Err(CoreError::ForkBeyondHead { .. })));
    }

    #[test]
    fn read_unknown_timeline_returns_error() {
        let store = MemoryStore::new();
        let unknown = TimelineId::new();
        let result = store.read(unknown, SeqRange::all());
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    fn append_to_unknown_timeline_returns_error() {
        let mut store = MemoryStore::new();
        let unknown = TimelineId::new();
        let entity = EntityId::new();
        let result = store.append(unknown, &[make_draft(entity, b"x")]);
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    fn list_timelines_returns_all() {
        let mut store = MemoryStore::new();
        store.create_timeline("a").unwrap();
        store.create_timeline("b").unwrap();
        store.create_timeline("c").unwrap();
        let list = store.list_timelines().unwrap();
        assert_eq!(list.len(), 3);
    }

    #[test]
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
    fn empty_batch_append_returns_empty() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let result = store.append(tl.id(), &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
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
    fn explicit_wall_time_is_preserved() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(123_456_789);
        let draft = make_draft(entity, b"pinned")
            .with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).unwrap();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
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
    fn memory_store_default_equals_new() {
        // Exercises MemoryStore::default()
        let store: MemoryStore = MemoryStore::default();
        // A fresh default store has no timelines.
        let list = store.list_timelines().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at for multi-level fork (parent timeline branch).
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();

        // Append 3 events to root.
        store
            .append(root.id(), &[
                make_draft(entity, b"r1"),
                make_draft(entity, b"r2"),
                make_draft(entity, b"r3"),
            ])
            .unwrap();

        // Fork root at seq 2 to get child.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").unwrap();

        // Append 2 events to child.
        store
            .append(child.id(), &[
                make_draft(entity, b"c1"),
                make_draft(entity, b"c2"),
            ])
            .unwrap();

        // Fork child at seq 1 (its own event c1) to get grandchild.
        let grandchild = store.fork(child.id(), Seq::from_u64(1), "grandchild").unwrap();

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

}
