//! The on-demand Projection fold of a committed Timeline prefix (ADR-141 §9).
//!
//! A Gateway Projection Cut is the fold of the committed Events with
//! `seq <= at_seq`, through a fresh [`Reducer`] and a fresh
//! [`StateRegistry`], so it gets the core exclusions unchanged: geographic
//! and consent Events never reach the reducer, and `projects_event` filters
//! before an entity is created. The fold reads no clock, store, backend,
//! network or randomness.
//!
//! The caller feeds the prefix in chunks with
//! [`ProjectionFoldV1::fold_projection_chunk_v1`]. A chunk out of Timeline
//! Order is refused whole, so a fold either sees every chunk or answers no
//! page. A page lists entries by entity ULID bytes, ascending, and every page
//! of one cut carries the same `state_root`.

use std::{collections::BTreeMap, ops::Bound};

use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, Hash, Reducer, Seq, State, StateRegistry, TimelineId,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

/// Domain of a Projection entry's `state_digest` (ADR-141 P26, D19, D22).
pub const PROJECTION_STATE_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.GatewayProjectionState.v1";

/// Domain of a Projection's `provenance.digest` (ADR-141 P28).
pub const PROJECTION_PROVENANCE_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.GatewayProjection.v1";

/// Largest number of entries one Projection page holds (`page_items`, ADR-141 P22).
pub const MAX_PROJECTION_PAGE_ENTRIES_V1: usize = 100;

/// The last Event a reducer projected for one entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedEventV1 {
    /// The Event's exact payload bytes.
    pub payload: CanonicalBytes,
    /// The Event's ID.
    pub event_id: EventId,
    /// The Event's Timeline sequence.
    pub seq: Seq,
    /// The Event's causation, if any.
    pub causation_id: Option<EventId>,
}

impl ProjectedEventV1 {
    fn from_projected_event(event: &Event) -> Self {
        Self {
            payload: event.payload.clone(),
            event_id: event.id,
            seq: event.seq,
            causation_id: event.causation_id,
        }
    }

    /// The entry's `state_digest` (ADR-141 P26, D19, D22).
    ///
    /// BLAKE3 over the domain, `0x00`, the payload, the 16 Event ID bytes, the
    /// 8 big-endian `seq` bytes, and the causation flag: `0x00` without a
    /// causation, or `0x01` followed by the 16 causation ID bytes.
    #[must_use]
    pub fn projection_state_digest_v1(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROJECTION_STATE_DIGEST_DOMAIN_V1);
        hasher.update(&[0]);
        hasher.update(self.payload.as_slice());
        hasher.update(&self.event_id.inner().to_bytes());
        hasher.update(&self.seq.as_u64().to_be_bytes());
        hasher.update(&[u8::from(self.causation_id.is_some())]);
        if let Some(causation) = self.causation_id {
            hasher.update(&causation.inner().to_bytes());
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}

/// One entry of a Projection page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionEntryV1 {
    /// The State's entity.
    pub entity_id: EntityId,
    /// The folded State.
    pub state: State,
    /// The last Event the reducer projected for the entity.
    pub last_projected: ProjectedEventV1,
    /// The entry's `state_digest`, computed from `last_projected`.
    pub state_digest: Hash,
}

/// One page of a Projection cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionPageV1 {
    /// The page's entries, by entity ULID bytes, ascending.
    pub entries: Vec<ProjectionEntryV1>,
    /// Whether entities of the cut follow the last entry.
    pub more_remain: bool,
    /// The digest over every entity of the cut; independent of the page.
    pub state_root: Hash,
}

/// A Projection page size from 1 to [`MAX_PROJECTION_PAGE_ENTRIES_V1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionPageLimitV1(usize);

impl ProjectionPageLimitV1 {
    /// The limit `entries`, or `None` outside 1 to [`MAX_PROJECTION_PAGE_ENTRIES_V1`].
    #[must_use]
    pub const fn projection_page_limit_v1(entries: usize) -> Option<Self> {
        if entries == 0 || entries > MAX_PROJECTION_PAGE_ENTRIES_V1 {
            None
        } else {
            Some(Self(entries))
        }
    }

    /// The number of entries.
    #[must_use]
    pub const fn projection_page_entries_v1(self) -> usize {
        self.0
    }
}

/// Why a Projection fold refused a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionFoldErrorV1 {
    /// An Event's `seq` does not exceed the previous Event's `seq`; gaps are accepted.
    OutOfTimelineOrder,
}

/// An on-demand fold of a committed Timeline prefix up to `at_seq`, fed in chunks.
pub struct ProjectionFoldV1 {
    reducer: Box<dyn Reducer>,
    at_seq: Seq,
    registry: StateRegistry,
    last_projected: BTreeMap<EntityId, ProjectedEventV1>,
    last_seq: Option<Seq>,
}

impl ProjectionFoldV1 {
    /// A fold of the cut `at_seq` through the fresh `reducer`.
    #[must_use]
    pub fn for_projection_cut_v1(reducer: Box<dyn Reducer>, at_seq: Seq) -> Self {
        Self {
            reducer,
            at_seq,
            registry: StateRegistry::new(),
            last_projected: BTreeMap::new(),
            last_seq: None,
        }
    }

    /// Fold the next chunk of committed Events, in Timeline Order.
    ///
    /// Only Events with `seq <= at_seq` are folded.
    ///
    /// # Errors
    /// Returns [`ProjectionFoldErrorV1::OutOfTimelineOrder`], folding nothing
    /// of the chunk, when an Event's `seq` does not exceed the previous one,
    /// in this chunk or the chunk before it.
    pub fn fold_projection_chunk_v1(
        &mut self,
        chunk: &[Event],
    ) -> Result<(), ProjectionFoldErrorV1> {
        let mut previous = self.last_seq;
        for event in chunk {
            if previous.is_some_and(|seq| event.seq <= seq) {
                return Err(ProjectionFoldErrorV1::OutOfTimelineOrder);
            }
            previous = Some(event.seq);
        }
        self.last_seq = previous;
        let at_seq = self.at_seq;
        for event in chunk.iter().take_while(|event| event.seq <= at_seq) {
            if self.registry.apply_projected(self.reducer.as_ref(), event) {
                self.last_projected
                    .insert(event.entity, ProjectedEventV1::from_projected_event(event));
            }
        }
        Ok(())
    }

    /// The `state_root` of the cut folded so far (ADR-141 P28).
    ///
    /// BLAKE3 over the concatenation, by entity, of the 16 entity ID bytes and
    /// the 32 `state_digest` bytes of every entity; BLAKE3 of the empty input
    /// for an empty cut.
    #[must_use]
    pub fn projection_state_root_v1(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for (entity, last) in &self.last_projected {
            hasher.update(&entity.inner().to_bytes());
            hasher.update(last.projection_state_digest_v1().as_bytes());
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// The page of at most `limit` entries whose entities follow `after`.
    #[must_use]
    pub fn projection_page_v1(
        &self,
        after: Option<EntityId>,
        limit: ProjectionPageLimitV1,
    ) -> ProjectionPageV1 {
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut remaining = self.last_projected.range((lower, Bound::Unbounded));
        let entries = remaining
            .by_ref()
            .take(limit.projection_page_entries_v1())
            .map(|(entity, last)| ProjectionEntryV1 {
                entity_id: *entity,
                state: self.registry.get_or_default(entity),
                last_projected: last.clone(),
                state_digest: last.projection_state_digest_v1(),
            })
            .collect();
        ProjectionPageV1 {
            entries,
            more_remain: remaining.next().is_some(),
            state_root: self.projection_state_root_v1(),
        }
    }
}

/// Fold `events`, the committed prefix in Timeline Order, and answer one page.
///
/// The single-chunk form of [`ProjectionFoldV1`].
///
/// # Errors
/// Returns [`ProjectionFoldErrorV1::OutOfTimelineOrder`] when `events` is not
/// in Timeline Order.
pub fn fold_projection_page_v1(
    reducer: Box<dyn Reducer>,
    events: &[Event],
    at_seq: Seq,
    after: Option<EntityId>,
    limit: ProjectionPageLimitV1,
) -> Result<ProjectionPageV1, ProjectionFoldErrorV1> {
    let mut fold = ProjectionFoldV1::for_projection_cut_v1(reducer, at_seq);
    fold.fold_projection_chunk_v1(events)?;
    Ok(fold.projection_page_v1(after, limit))
}

/// A Projection's `provenance.digest` (ADR-141 P28).
///
/// BLAKE3 over the domain, `0x00`, and the RFC 8949 §4.2.1 deterministic CBOR
/// array `["host-derived", timeline_id, at_seq, owner, state_root]`, with the
/// Timeline ID as ULID text and `state_root` as a 32-byte byte string.
#[must_use]
pub fn projection_provenance_digest_v1(
    timeline_id: TimelineId,
    at_seq: Seq,
    owner: &str,
    state_root: &Hash,
) -> Hash {
    let mut cbor = Vec::new();
    push_projection_cbor_head(&mut cbor, 4, 5);
    push_projection_cbor_text(&mut cbor, "host-derived");
    push_projection_cbor_text(&mut cbor, &timeline_id.to_string());
    push_projection_cbor_head(&mut cbor, 0, at_seq.as_u64());
    push_projection_cbor_text(&mut cbor, owner);
    push_projection_cbor_head(&mut cbor, 2, 32);
    cbor.extend_from_slice(state_root.as_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROJECTION_PROVENANCE_DIGEST_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(&cbor);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Append the shortest RFC 8949 head of `major` type carrying `value`.
fn push_projection_cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let initial = major << 5;
    if let Ok(small @ 0..=23) = u8::try_from(value) {
        out.push(initial + small);
    } else if let Ok(byte) = u8::try_from(value) {
        out.extend([initial + 24, byte]);
    } else if let Ok(short) = u16::try_from(value) {
        out.push(initial + 25);
        out.extend(short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(value) {
        out.push(initial + 26);
        out.extend(word.to_be_bytes());
    } else {
        out.push(initial + 27);
        out.extend(value.to_be_bytes());
    }
}

/// Append `text` as a CBOR text string.
fn push_projection_cbor_text(out: &mut Vec<u8>, text: &str) {
    push_projection_cbor_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}
