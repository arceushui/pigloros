//! In-memory `EventStore` for tests and single-process use.
//!
//! Fork is copy-on-write: a child stores only its own events.
//! Reading from a forked child transparently stitches parent `0..fork_seq` + child events.
//! Multi-level fork chains are supported: a child of a child walks the chain recursively.

use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use pos_core::{
    clock::{AdmissionClock, Seq, SystemAdmissionClock, WallTime},
    crypto::Hash,
    error::CoreError,
    event::{Event, EventDraft, Kind},
    geo_admission::{
        GeoLocationAdmissionFingerprintV1, GeoLocationAdmissionIntentV1,
        GeoLocationAdmissionLinkV1, GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1,
        GeoLocationAdmissionSnapshotV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
        GeoLocationReplayVerifier,
    },
    geo_cell_admission::{
        AdmissionConsentRecordV1, AdmissionEntitlementSnapshotV1, AdmissionSnapshotHash,
        AdmissionSnapshotId, GeoCellAdmissionFenceV1, GeographicAdmissionAdmin,
        GeographicAdmissionConsentResolver, GeographicAdmissionOutcome, GeographicAdmissionStore,
        GeographicObservationV1, GeographicReplayEvidenceV1, GeographicReplayVerifier,
        ValidatedGeographicAdmissionV1,
    },
    hasher::Hasher,
    ids::{EventId, TimelineId},
    owntracks_enrollment::{
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStateV1, OwnTracksEnrollmentStatusV1,
        OwnTracksEnrollmentStore,
    },
    owntracks_ingress::{
        OwnTracksIngressInputV1, OwnTracksIngressStore, PreparedOwnTracksIngressV1,
    },
    store::{
        checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, AppendIdentity,
        AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome,
        SeqRange,
    },
    timeline::{Timeline, TimelineMeta},
    ConsentAppendPermit, GEOGRAPHIC_EVENT_TYPE,
};

#[cfg(test)]
thread_local! {
    /// Test-only evidence that bounded reads inspect only selected Event slots.
    static BOUNDED_EVENTS_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to prove the elapsed bound covers Event materialization.
    static BOUNDED_CLONE_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the planning elapsed guard.
    static BOUNDED_PLAN_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the fork-chain elapsed guard.
    static BOUNDED_CHAIN_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the per-Event planning elapsed guard.
    static BOUNDED_EVENT_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the materialization-start elapsed guard.
    static BOUNDED_MATERIALIZE_START_DELAY_MILLIS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the final materialization elapsed guard.
    static BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn bounded_clone_delay_for_test() {
    let delay_millis = BOUNDED_CLONE_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_plan_delay_for_test() {
    let delay_millis = BOUNDED_PLAN_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_chain_delay_for_test() {
    let delay_millis = BOUNDED_CHAIN_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_event_delay_for_test() {
    let delay_millis = BOUNDED_EVENT_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_materialize_start_delay_for_test() {
    let delay_millis = BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_materialize_final_delay_for_test() {
    let delay_millis = BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
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
    /// Durable-equivalent markers for bounded revocation cleanup continuation.
    pending_append_identity_cleanup: Vec<AppendDedupScope>,
    /// Durable-equivalent marker for Timelines containing protected evidence.
    geographic_timelines: HashSet<TimelineId>,
    /// The sole current authorization state for protected geographic admission.
    owntracks_enrollment: OwnTracksEnrollmentStateV1,
    /// Private keyed deduplication records for protected geographic admission.
    geographic_admission_dedup:
        HashMap<GeoLocationAdmissionFingerprintV1, GeographicAdmissionDedupRecord>,
    /// Immutable admission snapshots, retained for the lifetime of their Event.
    geographic_admission_snapshots: HashMap<EventId, GeoLocationAdmissionSnapshotV1>,
    /// Immutable Event-to-snapshot links, uniquely keyed by `(TimelineId, EventId)`.
    geographic_admission_links: HashMap<(TimelineId, EventId), GeoLocationAdmissionLinkV1>,
    /// Current core-owned binding/consent/entitlement fences for `geo.cell`.
    geographic_cell_fences: HashMap<(TimelineId, pos_core::EntityId), GeoCellAdmissionFenceV1>,
    /// Typed local adapter view of the authoritative immutable consent resolver.
    geographic_cell_consent_records: HashMap<(AdmissionSnapshotId, u64), AdmissionConsentRecordV1>,
    /// Private seven-day exact-intent deduplication for `geo.cell`.
    geographic_cell_dedup:
        HashMap<pos_core::GeographicAdmissionFingerprintV1, GeographicCellDedupRecord>,
    /// Immutable `geo.cell` admission snapshots keyed by their canonical ID.
    geographic_cell_snapshots: HashMap<AdmissionSnapshotId, AdmissionEntitlementSnapshotV1>,
    /// Immutable `geo.cell` Event-to-snapshot links.
    geographic_cell_links: HashMap<(TimelineId, EventId), GeographicCellLink>,
    /// Trusted Gateway authority bound to this adapter's protected append port.
    consent_authority_permit: Option<ConsentAppendPermit>,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
}

#[derive(Clone, Copy)]
struct BoundedSegmentPage {
    timeline: TimelineId,
    raw_start: u64,
    take: usize,
    logical_offset: u64,
}

struct BoundedSegmentRequest<'a> {
    chain: &'a [TimelineId],
    index: usize,
    timeline: TimelineId,
    logical_offset: u64,
    from: u64,
    to: u64,
    remaining: usize,
    bounds: EventReadBounds,
    started: Instant,
    total_bytes: &'a mut usize,
}

fn bounded_elapsed_error(started: Instant, maximum_micros: u64) -> Option<CoreError> {
    let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    (elapsed_micros > maximum_micros).then_some(CoreError::ReadTimeTooLarge { elapsed_micros })
}

#[inline(never)]
fn read_event_by_id(
    store: &MemoryStore,
    timeline: TimelineId,
    event_id: EventId,
) -> Result<Option<Event>, CoreError> {
    store
        .ensure_generic_timeline_visibility(timeline)
        .and_then(|()| store.fork_chain(timeline))
        .and_then(|chain| {
            for (index, timeline_id) in chain.timelines.iter().enumerate() {
                let prefix = chain.segment_prefix(index)?;
                let limit = chain.segment_length(store, index, *timeline_id)?;
                if let Some(event) = store
                    .state(*timeline_id)
                    .events
                    .iter()
                    .find(|event| event.seq.as_u64() <= limit && event.id == event_id)
                    .cloned()
                {
                    return MemoryStore::logical_event(prefix, event).map(Some);
                }
            }
            Ok(None)
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
            if store
                .owntracks_enrollment
                .permits_geographic_admission_target(id)
            {
                store.owntracks_enrollment = store
                    .owntracks_enrollment
                    .clone()
                    .revoke()
                    .unwrap_or_else(|_| OwnTracksEnrollmentStateV1::absent());
            }
            store
                .geographic_admission_dedup
                .retain(|_, record| record.timeline != id);
            store
                .geographic_admission_snapshots
                .retain(|event_id, _| !event_ids.contains(event_id));
            store
                .geographic_admission_links
                .retain(|(timeline, event_id), _| *timeline != id && !event_ids.contains(event_id));
            store
                .geographic_cell_fences
                .retain(|(timeline, _), _| *timeline != id);
            store
                .geographic_cell_dedup
                .retain(|_, record| record.timeline != id);
            store
                .geographic_cell_snapshots
                .retain(|_, snapshot| snapshot.timeline() != id);
            // Consent records are authoritative resolver state. Their lifecycle
            // is owned by the ADR-034 resolver, not by Timeline sidecar cleanup.
            store
                .geographic_cell_links
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

#[derive(Clone)]
struct GeographicCellDedupRecord {
    timeline: TimelineId,
    entity: pos_core::EntityId,
    intent: pos_core::GeographicAdmissionIntentV1,
    event_id: EventId,
    event_seq: Seq,
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
    expires_at: WallTime,
}

#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct GeographicCellLink {
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
    snapshot_cbor: pos_core::CanonicalBytes,
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

impl ForkChain {
    fn segment_prefix(&self, index: usize) -> Result<u64, CoreError> {
        if index == 0 {
            Ok(0)
        } else {
            self.fork_seqs
                .get(index - 1)
                .copied()
                .map(Seq::as_u64)
                .ok_or_else(|| {
                    CoreError::Storage("Fork chain is missing a logical prefix".to_owned())
                })
        }
    }

    fn segment_length(
        &self,
        store: &MemoryStore,
        index: usize,
        timeline: TimelineId,
    ) -> Result<u64, CoreError> {
        let prefix = self.segment_prefix(index)?;
        let local_head = store.state(timeline).timeline.head.as_u64();
        let length = match self.fork_seqs.get(index).copied() {
            Some(fork) => fork.as_u64().checked_sub(prefix).ok_or_else(|| {
                CoreError::Storage(format!(
                    "Fork point precedes inherited history for timeline {timeline}"
                ))
            })?,
            None => local_head,
        };
        if length > local_head {
            return Err(CoreError::Storage(format!(
                "Fork point exceeds parent logical Event head for timeline {timeline}"
            )));
        }
        Ok(length)
    }
}

#[derive(Clone)]
struct TimelineState {
    timeline: Timeline,
    events: Vec<Event>,
    chain_head: Hash,
}

impl TimelineState {
    const fn new(timeline: Timeline, chain_head: Hash) -> Self {
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
            pending_append_identity_cleanup: Vec::new(),
            geographic_timelines: HashSet::new(),
            owntracks_enrollment: OwnTracksEnrollmentStateV1::absent(),
            geographic_admission_dedup: HashMap::new(),
            geographic_admission_snapshots: HashMap::new(),
            geographic_admission_links: HashMap::new(),
            geographic_cell_fences: HashMap::new(),
            geographic_cell_consent_records: HashMap::new(),
            geographic_cell_dedup: HashMap::new(),
            geographic_cell_snapshots: HashMap::new(),
            geographic_cell_links: HashMap::new(),
            consent_authority_permit: None,
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
        let logical_prefix = self.logical_prefix(timeline)?;
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
        event.and_then(|event| {
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
            Self::logical_event(logical_prefix, event)
                .map(|event| Some(AppendOrDuplicateOutcome::Appended(Box::new(event))))
        })
    }

    fn timeline(&self, id: TimelineId) -> Result<&Timeline, CoreError> {
        self.timelines
            .get(&id)
            .map_or(Err(CoreError::TimelineNotFound(id)), |state| {
                Ok(&state.timeline)
            })
    }

    fn logical_prefix(&self, timeline: TimelineId) -> Result<u64, CoreError> {
        self.timeline(timeline).map(|timeline| {
            timeline
                .meta
                .fork_point
                .map_or(0, |(_, fork)| fork.as_u64())
        })
    }

    fn logical_event(prefix: u64, mut event: Event) -> Result<Event, CoreError> {
        event.seq =
            Seq::from_u64(prefix.checked_add(event.seq.as_u64()).ok_or_else(|| {
                CoreError::Storage("logical Timeline sequence overflow".to_owned())
            })?);
        Ok(event)
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
            signature_identity: None,
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
    /// Returns events sorted by seq, stitching parent `0..fork_seq` + child events.
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
                self.timeline(*tid).and_then(|_| {
                    let state = self.state(*tid);
                    let events = &state.events;
                    let length = chain.segment_length(self, i, *tid)?;
                    all.extend(
                        events
                            .iter()
                            .filter(|event| event.seq.as_u64() <= length)
                            .cloned(),
                    );
                    Ok(all)
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
        let started = Instant::now();
        if bounds.max_elapsed_micros() == 0 {
            return Err(CoreError::ReadTimeTooLarge { elapsed_micros: 0 });
        }
        let chain = self.fork_chain_bounded(
            timeline_id,
            bounds.max_fork_depth(),
            started,
            bounds.max_elapsed_micros(),
        )?;
        self.plan_bounded_events(&chain, range, bounds, started)
            .and_then(|plans| self.materialize_bounded_events(&plans, bounds, started))
    }

    fn plan_bounded_events(
        &self,
        chain: &[TimelineId],
        range: SeqRange,
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<BoundedSegmentPage>, CoreError> {
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        let mut logical_offset = 0_u64;
        let mut remaining = bounds.max_events();
        let mut total_bytes = 0_usize;
        let mut plans = Vec::new();

        for (index, timeline) in chain.iter().enumerate() {
            let planned = self.plan_bounded_segment(BoundedSegmentRequest {
                chain,
                index,
                timeline: *timeline,
                logical_offset,
                from,
                to,
                remaining,
                bounds,
                started,
                total_bytes: &mut total_bytes,
            })?;
            if let Some(plan) = planned {
                remaining -= plan.take;
                plans.push(plan);
            }
            let segment_len =
                self.bounded_segment_length(chain, index, *timeline, logical_offset)?;
            logical_offset = logical_offset.saturating_add(segment_len);
            if remaining == 0 || logical_offset >= to {
                break;
            }
        }
        Ok(plans)
    }

    fn plan_bounded_segment(
        &self,
        request: BoundedSegmentRequest<'_>,
    ) -> Result<Option<BoundedSegmentPage>, CoreError> {
        let BoundedSegmentRequest {
            chain,
            index,
            timeline,
            logical_offset,
            from,
            to,
            remaining,
            bounds,
            started,
            total_bytes,
        } = request;
        #[cfg(test)]
        bounded_plan_delay_for_test();
        if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
            return Err(error);
        }
        let state = self.state(timeline);
        let events = &state.events;
        let event_count = u64::try_from(events.len()).unwrap_or(u64::MAX);
        let boundary_is_valid = if events.is_empty() {
            state.timeline.head == Seq::ZERO
        } else {
            state.timeline.head.as_u64() == event_count
                && events[0].seq == Seq::from_u64(1)
                && events[events.len() - 1].seq == Seq::from_u64(event_count)
        };
        if !boundary_is_valid {
            return Err(CoreError::Storage(format!(
                "timeline {timeline} violates the contiguous Event sequence invariant"
            )));
        }
        let segment_len = self.bounded_segment_length(chain, index, timeline, logical_offset)?;
        let Some(page) = crate::stitch::plan_page(logical_offset, segment_len, from, to, remaining)
        else {
            return Ok(None);
        };
        let start_index = usize::try_from(page.raw_start - 1).unwrap_or(usize::MAX);
        let end_index = start_index.saturating_add(page.take);
        let slice = &events[start_index..end_index];
        for (offset, event) in slice.iter().enumerate() {
            #[cfg(test)]
            bounded_event_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                return Err(error);
            }
            #[cfg(test)]
            BOUNDED_EVENTS_EXAMINED.with(|count| count.set(count.get().saturating_add(1)));
            let raw_seq = page
                .raw_start
                .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
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
            *total_bytes =
                (*total_bytes).saturating_add(payload_size.saturating_add(event_type_size));
            if *total_bytes > bounds.max_total_bytes() {
                return Err(CoreError::ReadBytesTooLarge { size: *total_bytes });
            }
        }
        Ok(Some(BoundedSegmentPage {
            timeline,
            raw_start: page.raw_start,
            take: page.take,
            logical_offset,
        }))
    }

    fn bounded_segment_length(
        &self,
        chain: &[TimelineId],
        index: usize,
        timeline: TimelineId,
        logical_offset: u64,
    ) -> Result<u64, CoreError> {
        let event_count = u64::try_from(self.state(timeline).events.len()).unwrap_or(u64::MAX);
        let fork_cap = chain.get(index + 1).and_then(|child| {
            self.timelines[child]
                .timeline
                .meta
                .fork_point
                .map(|(_, seq)| seq)
        });
        let segment_len = fork_cap.map_or(Ok(event_count), |cap| {
            cap.as_u64().checked_sub(logical_offset).ok_or_else(|| {
                CoreError::Storage(format!(
                    "Fork point precedes inherited history for timeline {timeline}"
                ))
            })
        })?;
        if segment_len > event_count {
            return Err(CoreError::Storage(format!(
                "Fork point exceeds parent logical Event head for timeline {timeline}"
            )));
        }
        Ok(segment_len)
    }

    fn materialize_bounded_events(
        &self,
        plans: &[BoundedSegmentPage],
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<Event>, CoreError> {
        let mut selected = Vec::new();
        for plan in plans {
            #[cfg(test)]
            bounded_materialize_start_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                return Err(error);
            }
            let events = &self.state(plan.timeline).events;
            let start_index = usize::try_from(plan.raw_start - 1).unwrap_or(usize::MAX);
            let end_index = start_index.saturating_add(plan.take);
            for event in &events[start_index..end_index] {
                let mut event = event.clone();
                #[cfg(test)]
                bounded_clone_delay_for_test();
                event.seq = Seq::from_u64(plan.logical_offset.saturating_add(event.seq.as_u64()));
                selected.push(event);
                if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                    return Err(error);
                }
            }
        }
        #[cfg(test)]
        bounded_materialize_final_delay_for_test();
        if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
            return Err(error);
        }
        Ok(selected)
    }

    fn append_bounded_with_boundary(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
        gateway_consent: bool,
        permit: Option<ConsentAppendPermit>,
        cleanup_scope: Option<AppendDedupScope>,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        if gateway_consent {
            let bound_permit = self.consent_authority_permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent authority is not bound".to_owned())
            })?;
            let permit = permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent append permit is missing".to_owned())
            })?;
            if permit != bound_permit {
                return Err(CoreError::Storage(
                    "Gateway consent append permit does not match the bound authority".to_owned(),
                ));
            }
        }
        let validate = if gateway_consent {
            crate::ensure_gateway_consent_types
        } else {
            crate::ensure_non_geographic_drafts
        };
        validate(drafts, timeline)
            .and_then(|()| {
                if gateway_consent {
                    self.timeline(timeline).map(|_| ())
                } else {
                    self.ensure_generic_timeline_visibility(timeline)
                }
            })
            .and_then(|()| {
                // Visibility checked this key immediately above and no mutation
                // occurs between the check and this read.
                let timeline_state = &self.timelines[&timeline].timeline;
                let owned_head = timeline_state.head.as_u64();
                let logical_prefix = timeline_state
                    .meta
                    .fork_point
                    .map_or(0, |(_, fork)| fork.as_u64());
                let batch_len = u64::try_from(drafts.len()).unwrap_or(u64::MAX);
                let owner = if gateway_consent {
                    Some(crate::ensure_gateway_consent_drafts(
                        drafts,
                        timeline,
                        timeline_state.meta.owner,
                        logical_prefix.saturating_add(owned_head).saturating_add(1),
                    )?)
                } else {
                    None
                };
                if let Some(next_head) =
                    crate::bounded_owned_head(owned_head, batch_len, max_owned_events)?
                {
                    crate::checked_logical_head(logical_prefix, next_head)?;
                    let events =
                        self.append_visible_with_prefix(timeline, drafts, logical_prefix)?;
                    if let Some(scope) = cleanup_scope {
                        if !self.pending_append_identity_cleanup.contains(&scope) {
                            self.pending_append_identity_cleanup.push(scope);
                        }
                    }
                    if let Some(owner) = owner {
                        if let Some(state) = self.timelines.get_mut(&timeline) {
                            state.timeline.meta.owner = Some(owner);
                        }
                    }
                    Ok(Some(events))
                } else {
                    Ok(None)
                }
            })
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
        started: Instant,
        max_elapsed_micros: u64,
    ) -> Result<Vec<TimelineId>, CoreError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        let mut depth = 0_usize;
        loop {
            #[cfg(test)]
            bounded_chain_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, max_elapsed_micros) {
                return Err(error);
            }
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

    fn append_visible(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        let logical_prefix = self.logical_prefix(timeline)?;
        self.append_visible_with_prefix(timeline, drafts, logical_prefix)
    }

    fn append_visible_with_prefix(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        logical_prefix: u64,
    ) -> Result<Vec<Event>, CoreError> {
        let committed = {
            let (timelines, hasher) = (&mut self.timelines, &self.hasher);
            mutable_state(timelines, timeline).map(|state| {
                drafts
                    .iter()
                    .map(|draft| Self::append_one_to_state(state, draft, hasher.as_ref()))
                    .collect::<Vec<_>>()
            })
        };
        committed
            .inspect(|events| {
                self.event_ids.extend(events.iter().map(|event| event.id));
            })
            .and_then(|events| {
                events
                    .into_iter()
                    .map(|event| Self::logical_event(logical_prefix, event))
                    .collect()
            })
    }

    fn fork_visible_timeline(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
        let parent_head = self.logical_head(parent)?;
        if at_seq > parent_head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: parent_head.as_u64(),
            });
        }

        let meta = self
            .timelines
            .get(&parent)
            .and_then(|state| state.timeline.meta.owner)
            .map_or_else(
                || TimelineMeta::forked_from(parent, at_seq, name),
                |owner| TimelineMeta::forked_from_owned(parent, at_seq, name, owner),
            );
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

impl OwnTracksEnrollmentStore for MemoryStore {
    fn pair_owntracks_enrollment(
        &mut self,
        request: OwnTracksEnrollmentRequestV1,
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.timeline(request.timeline())?;
        self.owntracks_enrollment = self.owntracks_enrollment.clone().pair(&request)?;
        Ok(self.owntracks_enrollment.status())
    }

    fn owntracks_enrollment_status(
        &self,
    ) -> Result<pos_core::OwnTracksEnrollmentStatusViewV1, CoreError> {
        Ok(self.owntracks_enrollment.status_view())
    }

    fn rotate_owntracks_enrollment_verifier(
        &mut self,
        verifier: [u8; 32],
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.owntracks_enrollment = self.owntracks_enrollment.clone().rotate(verifier)?;
        Ok(self.owntracks_enrollment.status())
    }

    fn revoke_owntracks_enrollment(&mut self) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.owntracks_enrollment = self.owntracks_enrollment.clone().revoke()?;
        Ok(self.owntracks_enrollment.status())
    }
}

impl OwnTracksIngressStore for MemoryStore {
    fn prepare_owntracks_ingress(
        &mut self,
        input: OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, CoreError> {
        self.owntracks_enrollment.prepare_owntracks_ingress(&input)
    }
}

impl GeoLocationAdmissionStore for MemoryStore {
    fn protected_logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.logical_head_unchecked(timeline)
    }

    fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, CoreError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let admitted_at = self.clock.now()?;
        let permits_request = |store: &Self| {
            store
                .owntracks_enrollment
                .permits_geographic_admission(&request)
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
            return Ok(GeoLocationAdmissionOutcome::classify_retained_intent(
                request.intent(),
                record.intent,
                record.event_id,
            ));
        }

        let expires_at = checked_append_identity_expires_at(admitted_at)?;

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
            || self.hasher.hash_payload(link.snapshot_cbor()) != evidence.snapshot_hash()
        {
            return validation_failure();
        }
        Ok(())
    }
}

impl GeographicAdmissionAdmin for MemoryStore {
    fn set_geo_cell_admission_consent_record(
        &mut self,
        record: AdmissionConsentRecordV1,
    ) -> Result<(), CoreError> {
        if AdmissionSnapshotId::from_canonical(record.id().as_str()).is_err()
            || record.revision() == 0
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let key = (record.id().clone(), record.revision());
        if let Some(existing) = self.geographic_cell_consent_records.get(&key) {
            if existing != &record {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            }
            return Ok(());
        }
        self.geographic_cell_consent_records.insert(key, record);
        Ok(())
    }

    fn set_geo_cell_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: pos_core::EntityId,
        fence: GeoCellAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        if fence.draft().timeline() != timeline || fence.draft().entity() != entity {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        self.geographic_cell_fences
            .insert((timeline, entity), fence);
        Ok(())
    }
}

impl GeographicAdmissionConsentResolver for MemoryStore {
    fn resolve_admission_consent(
        &self,
        consent_record_id: &AdmissionSnapshotId,
        consent_revision: u64,
    ) -> Result<AdmissionConsentRecordV1, CoreError> {
        let record = self
            .geographic_cell_consent_records
            .get(&(consent_record_id.clone(), consent_revision))
            .cloned()
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        Ok(record)
    }
}

impl GeographicAdmissionStore for MemoryStore {
    #[allow(clippy::too_many_lines)]
    fn admit(
        &mut self,
        request: ValidatedGeographicAdmissionV1,
    ) -> Result<GeographicAdmissionOutcome, CoreError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let Ok(admitted_at) = self.clock.now() else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Some(fence) = self.geographic_cell_fences.get(&(timeline, entity)) else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        if !fence.permits(&request) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent_record = self.resolve_admission_consent(
            request.fence().draft().consent_record_id(),
            request.fence().draft().consent_revision(),
        )?;
        if !consent_record.matches_draft(request.fence().draft()) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let mut staged_dedup = self.geographic_cell_dedup.clone();
        staged_dedup.retain(|_, record| record.expires_at > admitted_at);
        if let Some(record) = staged_dedup
            .get(&request.fingerprint())
            .filter(|record| record.expires_at > admitted_at)
            .cloned()
        {
            if record.intent.as_persistence_bytes() != request.intent().as_persistence_bytes() {
                self.geographic_cell_dedup = staged_dedup;
                return Ok(GeographicAdmissionOutcome::Conflict);
            }
            let outcome = self
                .verified_geo_cell_duplicate(&record)
                .unwrap_or(GeographicAdmissionOutcome::OutcomeUnknown);
            if !outcome.is_outcome_unknown() {
                self.geographic_cell_dedup = staged_dedup;
            }
            return Ok(outcome);
        }
        let Ok(expires_at) = pos_core::checked_append_identity_expires_at(admitted_at) else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Some(existing_state) = self.timelines.get(&timeline) else {
            return Err(CoreError::TimelineNotFound(timeline));
        };
        let mut staged_state = existing_state.clone();
        let event_id = EventId::new();
        let event_seq = staged_state.timeline.head.next();
        let snapshot_id = AdmissionSnapshotId::new();
        let snapshot =
            AdmissionEntitlementSnapshotV1::new(snapshot_id.clone(), &request, event_id, event_seq);
        let snapshot_cbor = snapshot.canonical_bytes();
        let snapshot_hash = snapshot.hash();
        let observation = request.payload(snapshot_id.clone(), snapshot_hash);
        let payload = observation.encode();
        let payload_hash = self.hasher.hash_payload(&payload);
        let event_id_bytes = event_id.to_string();
        let next_chain_head = self.hasher.hash_event(
            &staged_state.chain_head,
            event_id_bytes.as_bytes(),
            &payload,
        );
        let event = Event {
            id: event_id,
            entity,
            event_type: Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE),
            payload,
            wall_time: admitted_at,
            seq: event_seq,
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        };
        staged_state.timeline.head = event_seq;
        staged_state.chain_head = next_chain_head;
        staged_state.events.push(event.clone());
        let link = GeographicCellLink {
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
            snapshot_cbor,
        };
        if event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || GeographicObservationV1::decode(&event.payload).is_err()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let dedup = GeographicCellDedupRecord {
            timeline,
            entity,
            intent: request.intent().clone(),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
            expires_at,
        };
        self.timelines.insert(timeline, staged_state);
        self.event_ids.insert(event.id);
        self.geographic_timelines.insert(timeline);
        self.geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot);
        self.geographic_cell_links
            .insert((timeline, event.id), link);
        staged_dedup.insert(request.fingerprint(), dedup);
        self.geographic_cell_dedup = staged_dedup;
        Ok(GeographicAdmissionOutcome::Accepted {
            persisted_event: Box::new(event.clone()),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id,
            snapshot_hash,
        })
    }
}

impl MemoryStore {
    fn verified_geo_cell_duplicate(
        &self,
        record: &GeographicCellDedupRecord,
    ) -> Option<GeographicAdmissionOutcome> {
        let state = self.timelines.get(&record.timeline)?;
        let event = state
            .events
            .iter()
            .find(|event| event.id == record.event_id)?;
        let record_event_seq = record.event_seq;
        if event.entity != record.entity
            || event.seq != record_event_seq
            || event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return None;
        }
        let observation =
            pos_core::geo_cell_admission::GeographicObservationV1::decode(&event.payload).ok()?;
        if observation.snapshot_id() != &record.snapshot_id
            || observation.snapshot_hash() != record.snapshot_hash
        {
            return None;
        }
        let snapshot = self.geographic_cell_snapshots.get(&record.snapshot_id)?;
        let snapshot_cbor = snapshot.canonical_bytes();
        if snapshot.hash() != record.snapshot_hash
            || snapshot.event_id() != record.event_id
            || snapshot.event_seq() != record.event_seq
        {
            return None;
        }
        let linkage = snapshot.linkage();
        let consent = self
            .resolve_admission_consent(linkage.consent_record_id(), linkage.consent_revision())
            .ok()?;
        if !consent.matches_linkage(&linkage) {
            return None;
        }
        let link = self
            .geographic_cell_links
            .get(&(record.timeline, record.event_id))?;
        if link.snapshot_id != record.snapshot_id
            || link.snapshot_hash != record.snapshot_hash
            || link.snapshot_cbor != snapshot_cbor
        {
            return None;
        }
        Some(GeographicAdmissionOutcome::Duplicate {
            event_id: record.event_id,
            event_seq: record.event_seq,
            snapshot_id: record.snapshot_id.clone(),
            snapshot_hash: record.snapshot_hash,
        })
    }
}

impl GeographicReplayVerifier for MemoryStore {
    fn verify_geo_cell_event(&self, evidence: GeographicReplayEvidenceV1) -> Result<(), CoreError> {
        let fail = || Err(CoreError::GeographicAdmissionValidationFailed);
        let Some(state) = self.timelines.get(&evidence.timeline()) else {
            return fail();
        };
        let Some(event) = state
            .events
            .iter()
            .find(|event| event.id == evidence.event_id())
        else {
            return fail();
        };
        if event.seq != evidence.event_seq()
            || event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || event.payload_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return fail();
        }
        let Ok(observation) =
            pos_core::geo_cell_admission::GeographicObservationV1::decode(&event.payload)
        else {
            return fail();
        };
        if observation.snapshot_id() != evidence.snapshot_id()
            || observation.snapshot_hash() != evidence.snapshot_hash()
        {
            return fail();
        }
        let Some(snapshot) = self.geographic_cell_snapshots.get(evidence.snapshot_id()) else {
            return fail();
        };
        let snapshot_cbor = snapshot.canonical_bytes();
        let evidence_snapshot_hash = evidence.snapshot_hash();
        if snapshot.hash() != evidence_snapshot_hash
            || snapshot.event_id() != evidence.event_id()
            || snapshot.event_seq() != evidence.event_seq()
            || snapshot.timeline() != evidence.timeline()
            || snapshot.entity() != event.entity
        {
            return fail();
        }
        let linkage = snapshot.linkage();
        let Ok(consent) =
            self.resolve_admission_consent(linkage.consent_record_id(), linkage.consent_revision())
        else {
            return fail();
        };
        if !consent.matches_linkage(&linkage) {
            return fail();
        }
        let Some(link) = self
            .geographic_cell_links
            .get(&(evidence.timeline(), evidence.event_id()))
        else {
            return fail();
        };
        if link.snapshot_id != *evidence.snapshot_id()
            || link.snapshot_hash != evidence.snapshot_hash()
            || link.snapshot_cbor != snapshot_cbor
        {
            return fail();
        }
        Ok(())
    }
}

impl MemoryStore {
    fn logical_head_unchecked(&self, id: TimelineId) -> Result<Seq, CoreError> {
        let chain = self.fork_chain(id)?;
        let mut logical_head = 0_u64;
        for (index, timeline) in chain.timelines.iter().enumerate() {
            let length = chain.segment_length(self, index, *timeline)?;
            logical_head = logical_head
                .checked_add(length)
                .ok_or_else(|| CoreError::Storage("logical Timeline head overflow".to_owned()))?;
        }
        Ok(Seq::from_u64(logical_head))
    }
}

impl EventStore for MemoryStore {
    fn bind_consent_authority(&mut self, permit: ConsentAppendPermit) -> Result<(), CoreError> {
        match self.consent_authority_permit {
            Some(existing) if existing != permit => Err(CoreError::Storage(
                "Gateway consent authority is already bound".to_owned(),
            )),
            Some(_) => Ok(()),
            None => {
                self.consent_authority_permit = Some(permit);
                Ok(())
            }
        }
    }

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
            .and_then(|()| self.append_visible(timeline, drafts))
    }

    fn append_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        self.append_bounded_with_boundary(timeline, drafts, max_owned_events, false, None, None)
    }

    fn append_consent_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        self.append_bounded_with_boundary(
            timeline,
            drafts,
            max_owned_events,
            true,
            Some(permit),
            None,
        )
    }

    fn append_consent_revocation_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
        cleanup_scope: AppendDedupScope,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        crate::ensure_gateway_consent_revocation(drafts, timeline)?;
        self.append_bounded_with_boundary(
            timeline,
            drafts,
            max_owned_events,
            true,
            Some(permit),
            Some(cleanup_scope),
        )
    }

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.append_or_duplicate_with_limit(timeline, identity, admitted_at, &draft, None)
            .and_then(crate::unbounded_append_outcome)
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
        self.pending_append_identity_cleanup
            .retain(|pending| *pending != scope);
        Ok(before.saturating_sub(self.append_identities.len()))
    }

    fn remove_append_identities_bounded(
        &mut self,
        scope: AppendDedupScope,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let mut matching: Vec<_> = self
            .append_identities
            .iter()
            .filter(|(_, record)| record.scope == scope)
            .map(|(key, record)| (record.expires_at, *key))
            .collect();
        matching.sort_unstable_by_key(|(expires_at, key)| (*expires_at, key.as_bytes()));
        let more_may_remain = matching.len() > limit.get();
        let removed = matching.len().min(limit.get());
        for (_, key) in matching.into_iter().take(removed) {
            self.append_identities.remove(&key);
        }
        if more_may_remain {
            if !self.pending_append_identity_cleanup.contains(&scope) {
                self.pending_append_identity_cleanup.push(scope);
            }
        } else {
            self.pending_append_identity_cleanup
                .retain(|pending| *pending != scope);
        }
        Ok(PurgeOutcome {
            removed,
            more_may_remain,
        })
    }

    fn pending_append_identity_cleanup(&mut self) -> Result<Option<AppendDedupScope>, CoreError> {
        Ok(self.pending_append_identity_cleanup.last().copied())
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
        self.timelines.get(&id).map_or(Ok(None), |state| {
            crate::generic_timeline_is_visible(Ok(self.geographic_timelines.contains(&id)))
                .map(|visible| visible.then(|| state.timeline.clone()))
        })
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.ensure_generic_timeline_visibility(id)?;
        self.logical_head_unchecked(id)
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        // Resolve fork parent before duplicate-id check (parity with SqliteStore).
        let chain = if let Some((parent, at_seq)) = meta.fork_point {
            self.ensure_generic_timeline_visibility(parent)
                .and_then(|()| {
                    let parent_head = self.logical_head(parent)?;
                    if at_seq > parent_head {
                        Err(CoreError::ForkBeyondHead {
                            fork_seq: at_seq.as_u64(),
                            head: parent_head.as_u64(),
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
        let logical_head = self.logical_head(timeline)?;
        if at_seq > logical_head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: logical_head.as_u64(),
            });
        }
        let mut hash = self.hasher.genesis_hash();
        if at_seq == Seq::ZERO {
            return Ok(hash);
        }
        for event in
            self.collect_events_in_range(timeline, SeqRange::bounded(Seq::from_u64(1), at_seq))?
        {
            let id_str = event.id.to_string();
            hash = self
                .hasher
                .hash_event(&hash, id_str.as_bytes(), &event.payload);
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
                    .unwrap_or_else(|| {
                        std::panic::resume_unwind(Box::new(
                            "test corruption targets an existing Timeline",
                        ))
                    })
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        geo_admission::{
            GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
            GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
            GeoLocationReplayVerifier,
        },
        geo_cell_admission::{
            hash_admission_consent_record_bytes, AdmissionConsentRecordV1,
            AdmissionEntitlementDraftV1, AdmissionEntitlementSnapshotV1, AdmissionSnapshotHash,
            AdmissionSnapshotId, GeoCellAdmissionFenceV1, GeoCellAdmissionInputV1,
            GeoCellAdmissionRequestV1, GeographicAdmissionAdmin, GeographicAdmissionStore,
            ValidatedGeoCellV1,
        },
        ids::{EntityId, EventId},
        store::{SeqRange, TimelineExport},
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore,
    };

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected memory-store fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing memory-store fixture value"))
            })
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful memory-store fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    fn geo_cell_consent_record(id: AdmissionSnapshotId, revision: u64) -> AdmissionConsentRecordV1 {
        AdmissionConsentRecordV1::from_persistence_parts(
            id,
            revision,
            CanonicalBytes::from_static(b"\xa1frecordggeo-cell"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn geo_cell_draft(
        timeline: TimelineId,
        entity: EntityId,
        consent_record_id: AdmissionSnapshotId,
        consent_revision: u64,
        purpose: &str,
        entitled_principals: Vec<EntityId>,
        visibility_scope: &str,
        maximum_h3_resolution: u8,
        admission_policy_version: u32,
        admission_epoch: u64,
    ) -> AdmissionEntitlementDraftV1 {
        let record = geo_cell_consent_record(consent_record_id.clone(), consent_revision);
        AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_record_id,
            consent_revision,
            hash_admission_consent_record_bytes(record.canonical_bytes()),
            purpose,
            entitled_principals,
            visibility_scope,
            maximum_h3_resolution,
            admission_policy_version,
            admission_epoch,
        )
        .test_ok()
    }

    fn pair_geographic_enrollment(
        store: &mut MemoryStore,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
    ) {
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline, entity, fence, [42; 32],
            ))
            .test_ok();
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
        let timeline = clock_error.create_timeline("clock-error").test_ok();
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
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());

        let mut overflow = MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(
            WallTime::from_micros(u64::MAX),
        )));
        let timeline = overflow.create_timeline("overflow").test_ok();
        assert!(overflow
            .append_intent_or_duplicate(timeline.id(), append_identity(2, 2), intent)
            .is_err());
        drop(timeline);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_clock_and_expiry_failures_leave_no_evidence() {
        let entity = EntityId::new();
        let mut clock_error = MemoryStore::with_clock(Box::new(ErrorClock));
        let timeline = clock_error.create_timeline("geo-clock-error").test_ok();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"geo-clock-error"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));
        pair_geographic_enrollment(
            &mut clock_error,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        assert!(clock_error.admit_geo_location(request).is_err());
        assert!(clock_error.state(timeline.id()).events.is_empty());
        assert!(clock_error.geographic_admission_dedup.is_empty());
        assert!(clock_error.geographic_admission_snapshots.is_empty());
        assert!(clock_error.geographic_admission_links.is_empty());

        let entity = EntityId::new();
        let mut overflow = MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(
            WallTime::from_micros(u64::MAX),
        )));
        let timeline = overflow.create_timeline("geo-expiry-overflow").test_ok();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"geo-expiry-overflow"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));
        pair_geographic_enrollment(
            &mut overflow,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        assert!(overflow.admit_geo_location(request).is_err());
        assert!(overflow.state(timeline.id()).events.is_empty());
        assert!(overflow.geographic_admission_dedup.is_empty());
        assert!(overflow.geographic_admission_snapshots.is_empty());
        assert!(overflow.geographic_admission_links.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn geo_cell_duplicate_verifier_rejects_private_corruption() {
        let mut store = MemoryStore::new();
        let timeline = store
            .create_timeline("geo-cell-private-corruption")
            .test_ok();
        let entity = EntityId::new();
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
            b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
        ))
        .test_ok();
        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok(),
            12,
            "private-corruption",
            vec![entity],
            "private",
            9,
            1,
            13,
        );
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            cell,
            pos_core::SourceTimeBucket::new(123),
            GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        assert!(store
            .set_geo_cell_admission_consent_record(
                AdmissionConsentRecordV1::from_persistence_parts(
                    request.fence().draft().consent_record_id().clone(),
                    0,
                    CanonicalBytes::from_static(b"zero-revision"),
                )
            )
            .is_err());
        assert!(store
            .set_geo_cell_admission_consent_record(
                AdmissionConsentRecordV1::from_persistence_parts(
                    request.fence().draft().consent_record_id().clone(),
                    request.fence().draft().consent_revision(),
                    CanonicalBytes::from_static(b"different-consent"),
                )
            )
            .is_err());
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();
        let accepted = store.admit(request.clone()).test_ok();
        let event_id = accepted.event_id().test_ok();
        let event_seq = accepted.event_seq().test_ok();
        let snapshot_id = accepted.snapshot_id().test_ok().clone();
        let snapshot_hash = accepted.snapshot_hash().test_ok();
        let fingerprint = request.fingerprint();
        let valid = store.geographic_cell_dedup[&fingerprint].clone();
        assert!(store.verified_geo_cell_duplicate(&valid).is_some());

        let consent_key = (
            request.fence().draft().consent_record_id().clone(),
            request.fence().draft().consent_revision(),
        );
        let consent = store
            .geographic_cell_consent_records
            .remove(&consent_key)
            .test_ok();
        assert!(store.admit(request.clone()).is_err());
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent.clone());
        let alternate = AdmissionConsentRecordV1::from_persistence_parts(
            consent_key.0.clone(),
            consent_key.1,
            CanonicalBytes::from_static(b"different-consent"),
        );
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), alternate);
        assert!(store.admit(request.clone()).is_err());
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent);

        let dedup_record = store.geographic_cell_dedup.remove(&fingerprint).test_ok();
        let timeline_state = store.timelines.remove(&timeline.id()).test_ok();
        assert!(store.admit(request.clone()).is_err());
        store.timelines.insert(timeline.id(), timeline_state);
        store
            .geographic_cell_dedup
            .insert(fingerprint, dedup_record);

        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FB0").test_ok(),
            request.fence().draft().consent_revision(),
            "different-intent",
            request.fence().draft().entitled_principals().to_vec(),
            request.fence().draft().visibility_scope(),
            request.fence().draft().maximum_h3_resolution(),
            request.fence().draft().admission_policy_version(),
            request.fence().draft().admission_epoch(),
        );
        let conflict = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            request.cell().clone(),
            request.source_time_bucket(),
            GeoCellAdmissionFenceV1::new(
                draft,
                *request.fence().binding_identity(),
                request.fence().binding_revision(),
                false,
            ),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                conflict.fence().draft().consent_record_id().clone(),
                conflict.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, conflict.fence().clone())
            .test_ok();
        assert!(store.admit(conflict).test_ok().is_conflict());
        store
            .geographic_cell_dedup
            .insert(fingerprint, valid.clone());
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();

        let timeline_state = store.timelines.remove(&timeline.id()).test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .timelines
            .insert(timeline.id(), timeline_state.clone());
        let mut empty_timeline_state = timeline_state.clone();
        empty_timeline_state.events.clear();
        store.timelines.insert(timeline.id(), empty_timeline_state);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.insert(timeline.id(), timeline_state);

        let mut bad = valid.clone();
        bad.timeline = TimelineId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.entity = EntityId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.event_id = EventId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.event_seq = Seq::from_u64(event_seq.as_u64() + 1);
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.snapshot_id = AdmissionSnapshotId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xff; 32]);
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());

        let original_event = store.timelines.get(&timeline.id()).test_ok().events[0].clone();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload_hash = Hash::zero();
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        assert!(store.admit(request.clone()).test_ok().is_outcome_unknown());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload = CanonicalBytes::from_static(b"not-a-geo-cell");
        corrupt_event.payload_hash = store.hasher.hash_payload(&corrupt_event.payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let replacement_id = AdmissionSnapshotId::new();
        let replacement_hash = AdmissionSnapshotHash::from_bytes([31; 32]);
        let replacement_payload = request.payload(replacement_id, replacement_hash).encode();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload = replacement_payload.clone();
        corrupt_event.payload_hash = store.hasher.hash_payload(&replacement_payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();

        let snapshot = store
            .geographic_cell_snapshots
            .remove(&snapshot_id)
            .test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot.clone());
        let bad_snapshot = AdmissionEntitlementSnapshotV1::new(
            snapshot_id.clone(),
            &request,
            EventId::new(),
            event_seq,
        );
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), bad_snapshot);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let bad_snapshot = AdmissionEntitlementSnapshotV1::new(
            snapshot_id.clone(),
            &request,
            event_id,
            event_seq.next(),
        );
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), bad_snapshot);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot);

        let link = store
            .geographic_cell_links
            .remove(&(timeline.id(), event_id))
            .test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), link.clone());
        let mut bad_link = link.clone();
        bad_link.snapshot_id = AdmissionSnapshotId::new();
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let mut bad_link = link.clone();
        bad_link.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xee; 32]);
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let mut bad_link = link.clone();
        bad_link.snapshot_cbor = CanonicalBytes::from_static(b"bad-snapshot");
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), link);

        let evidence = GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            original_event.payload_hash,
            snapshot_id.clone(),
            snapshot_hash,
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_ok());

        let consent_key = (
            request.fence().draft().consent_record_id().clone(),
            request.fence().draft().consent_revision(),
        );
        let consent = store
            .geographic_cell_consent_records
            .remove(&consent_key)
            .test_ok();
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent.clone());
        store.geographic_cell_consent_records.insert(
            consent_key.clone(),
            AdmissionConsentRecordV1::from_persistence_parts(
                consent_key.0.clone(),
                consent_key.1,
                CanonicalBytes::from_static(b"different-consent"),
            ),
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_consent_records
            .insert(consent_key, consent);

        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                TimelineId::new(),
                event_id,
                event_seq,
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                EventId::new(),
                event_seq,
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq.next(),
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                Hash::zero(),
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        let original_link = store
            .geographic_cell_links
            .get(&(timeline.id(), event_id))
            .test_ok()
            .clone();
        let mut bad_event = original_event.clone();
        bad_event.event_type = Kind::new("other.event");
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = bad_event;
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let mut bad_event = original_event.clone();
        bad_event.payload = CanonicalBytes::from_static(b"not-a-geo-cell");
        bad_event.payload_hash = store.hasher.hash_payload(&bad_event.payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = bad_event;
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                store.timelines[&timeline.id()].events[0].payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event;
        let original_snapshot = store
            .geographic_cell_snapshots
            .get(&snapshot_id)
            .test_ok()
            .clone();
        store.geographic_cell_snapshots.insert(
            snapshot_id.clone(),
            snapshot_id_snapshot(&request, snapshot_id.clone(), EventId::new(), event_seq),
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), original_snapshot);
        let removed_link = store
            .geographic_cell_links
            .remove(&(timeline.id(), event_id))
            .test_ok();
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), removed_link);
        store.geographic_cell_snapshots.remove(&snapshot_id);
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        let previous_snapshot = store.geographic_cell_snapshots.insert(
            snapshot_id.clone(),
            snapshot_id_snapshot(&request, snapshot_id.clone(), event_id, event_seq),
        );
        assert!(previous_snapshot.is_none());
        let mut bad_link = original_link.clone();
        bad_link.snapshot_id = AdmissionSnapshotId::new();
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), original_link.clone());
        let mut bad_link = original_link;
        bad_link.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xdd; 32]);
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verify_geo_cell_event(evidence).is_err());

        let retained_link = store
            .geographic_cell_links
            .values()
            .next()
            .test_ok()
            .clone();
        store
            .geographic_cell_links
            .insert((TimelineId::new(), event_id), retained_link);
        delete_visible_timeline(&mut store, timeline.id()).test_ok();
    }

    #[test]
    fn geo_cell_expiry_purge_is_atomic_when_later_admission_work_fails() {
        let mut store = MemoryStore::new();
        let timeline = store
            .create_timeline("geo-cell-expiry-purge-atomicity")
            .test_ok();
        let entity = EntityId::new();
        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok(),
            12,
            "expiry-purge",
            vec![entity],
            "private",
            9,
            1,
            13,
        );
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
                b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
            ))
            .test_ok(),
            pos_core::SourceTimeBucket::new(123),
            GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();
        assert!(store.admit(request.clone()).test_ok().is_accepted());
        let fingerprint = request.fingerprint();
        store
            .geographic_cell_dedup
            .get_mut(&fingerprint)
            .test_ok()
            .expires_at = WallTime::from_micros(0);
        store.timelines.remove(&timeline.id()).test_ok();

        assert!(store.admit(request).is_err());
        assert!(store.geographic_cell_dedup.contains_key(&fingerprint));
    }

    fn snapshot_id_snapshot(
        request: &GeoCellAdmissionRequestV1,
        snapshot_id: AdmissionSnapshotId,
        event_id: EventId,
        event_seq: Seq,
    ) -> AdmissionEntitlementSnapshotV1 {
        AdmissionEntitlementSnapshotV1::new(snapshot_id, request, event_id, event_seq)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_rejects_unknown_timeline_and_stale_internal_fence() {
        let entity = EntityId::new();
        let missing_timeline = TimelineId::new();
        let fence = GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9));
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            missing_timeline,
            entity,
            CanonicalBytes::from_static(b"geo-stale-timeline"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 9),
            ([4; 32], [5; 32]),
        ));
        let mut store = MemoryStore::default();

        assert!(store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                missing_timeline,
                entity,
                fence,
                [42; 32],
            ))
            .is_err());
        assert!(store.admit_geo_location(request).is_err());
        assert!(store.geographic_admission_dedup.is_empty());
        assert!(store.geographic_admission_snapshots.is_empty());
        assert!(store.geographic_admission_links.is_empty());
    }

    fn assert_missing_geo_fence_is_rejected(store: &mut MemoryStore, timeline: TimelineId) {
        let missing_fence_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                timeline,
                EntityId::new(),
                CanonicalBytes::from_static(b"missing-fence"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([4; 32], [5; 32]),
            ));
        let error = store.admit_geo_location(missing_fence_request).test_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&CoreError::GeographicAdmissionValidationFailed)
        );
    }

    #[test]
    fn geographic_admission_keeps_private_sidecars_in_lockstep_with_timeline_lifecycle() {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("protected").test_ok();
        let entity = EntityId::new();
        assert_missing_geo_fence_is_rejected(&mut store, timeline.id());
        pair_geographic_enrollment(
            &mut store,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));

        let event_id = store
            .admit_geo_location(request.clone())
            .test_ok()
            .event_id()
            .test_ok();
        let event = &store.state(timeline.id()).events[0];
        let snapshot = store
            .geographic_admission_snapshots
            .get(&event_id)
            .test_ok();
        let link = store
            .geographic_admission_links
            .get(&(timeline.id(), event_id))
            .test_ok();
        assert!(link
            .validate_for(snapshot, timeline.id(), event_id, event.seq)
            .is_ok());
        assert_eq!(store.geographic_admission_dedup.len(), 1);

        assert!(store.admit_geo_location(request).test_ok().is_duplicate());
        assert_eq!(store.geographic_admission_snapshots.len(), 1);
        assert_eq!(store.geographic_admission_links.len(), 1);

        let (retained_timeline, retained_entity) =
            (store.create_timeline("retained").test_ok(), EntityId::new());
        store.revoke_owntracks_enrollment().test_ok();
        pair_geographic_enrollment(
            &mut store,
            retained_timeline.id(),
            retained_entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let retained_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                retained_timeline.id(),
                retained_entity,
                CanonicalBytes::from_static(b"retained-v1-geo-location-payload"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 12),
                ([6; 32], [7; 32]),
            ));
        let retained_event_id = store
            .admit_geo_location(retained_request)
            .test_ok()
            .event_id()
            .test_ok();
        let deleted_event_link = store
            .geographic_admission_links
            .get(&(timeline.id(), event_id))
            .test_ok()
            .clone();
        store
            .geographic_admission_links
            .insert((retained_timeline.id(), event_id), deleted_event_link);
        let retained_event_link = store
            .geographic_admission_links
            .get(&(retained_timeline.id(), retained_event_id))
            .test_ok()
            .clone();
        store
            .geographic_admission_links
            .insert((timeline.id(), retained_event_id), retained_event_link);

        delete_visible_timeline(&mut store, timeline.id()).test_ok();
        assert_eq!(
            store.owntracks_enrollment.status(),
            OwnTracksEnrollmentStatusV1::Active
        );
        assert_eq!(store.geographic_admission_dedup.len(), 1);
        assert_eq!(store.geographic_admission_snapshots.len(), 1);
        assert_eq!(store.geographic_admission_links.len(), 1);
        assert!(store
            .geographic_admission_links
            .contains_key(&(retained_timeline.id(), retained_event_id)));
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
        let timeline = store.create_timeline("replay-verifier").test_ok();
        let entity = EntityId::new();
        pair_geographic_enrollment(
            &mut store,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let accepted = store
            .admit_geo_location(GeoLocationAdmissionRequestV1::from_input(
                GeoLocationAdmissionInputV1::new(
                    timeline.id(),
                    entity,
                    CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                    7,
                    ([1; 32], 8, [2; 32]),
                    (1, false, 10),
                    ([4; 32], [5; 32]),
                ),
            ))
            .test_ok();
        let event_id = accepted.event_id().test_ok();
        let event_seq = accepted.event_seq().test_ok();
        let event_hash = store.state(timeline.id()).events[0].payload_hash;
        let snapshot_hash = store.hasher.hash_payload(
            store
                .geographic_admission_links
                .get(&(timeline.id(), event_id))
                .test_ok()
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
            .test_err()
            .to_string()
            .contains("geographic admission validation failed"));
    }

    #[test]
    fn replay_verifier_accepts_only_exact_event_evidence() {
        let mut fixture = replay_fixture();

        assert!(fixture
            .store
            .verify_v1_event_snapshot_link(
                fixture.evidence(fixture.event_hash, fixture.snapshot_hash,)
            )
            .is_ok());
        fixture.store.revoke_owntracks_enrollment().test_ok();
        fixture.store.clock = Box::new(ErrorClock);
        assert!(fixture
            .store
            .verify_v1_event_snapshot_link(
                fixture.evidence(fixture.event_hash, fixture.snapshot_hash)
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
            .test_ok()
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
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                EventId::new(),
                fixture.event_seq,
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
        let snapshot = fixture
            .store
            .geographic_admission_snapshots
            .remove(&fixture.event_id)
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, snapshot);
        let mismatched_snapshot =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                fixture.timeline,
                EntityId::new(),
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([6; 32], [7; 32]),
            ))
            .snapshot()
            .clone();
        let original_snapshot = fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, mismatched_snapshot)
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, original_snapshot);
        let link = fixture
            .store
            .geographic_admission_links
            .remove(&(fixture.timeline, fixture.event_id))
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_links
            .insert((fixture.timeline, fixture.event_id), link);
        fixture.store.state_mut(fixture.timeline).test_ok().events[0].event_type =
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
        let tl = store.create_timeline("main").test_ok();
        let got = store.get_timeline(tl.id()).test_ok();
        assert_eq!(got.as_ref().map(Timeline::id), Some(tl.id()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_and_read_events() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts = vec![
            make_draft(entity, b"first"),
            make_draft(entity, b"second"),
            make_draft(entity, b"third"),
        ];
        let committed = store.append(tl.id(), &drafts).test_ok();
        assert_eq!(committed.len(), 3);

        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), b"first");
        assert_eq!(events[1].payload.as_slice(), b"second");
        assert_eq!(events[2].payload.as_slice(), b"third");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_inherited_event_type_before_clone() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("x".repeat(5)),
            CanonicalBytes::from_static(b"x"),
        );
        store.append(root.id(), &[oversized]).test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let payload_error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(0, 5, usize::MAX, usize::MAX),
            )
            .test_err();
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
            .test_err();

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
            .test_ok();
        assert_eq!(events.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_aggregate_event_bytes_before_clone() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("aggregate-bytes").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"1234")),
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"5678")),
                ],
            )
            .test_ok();

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 9),
            )
            .test_err();
        assert!(matches!(error, CoreError::ReadBytesTooLarge { size: 10 }));

        let events = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 10),
            )
            .test_ok();
        assert_eq!(events.len(), 2);

        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 0),
            )
            .test_err();
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_CLONE_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_CLONE_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_PLAN_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_PLAN_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        let child = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-time-child")
            .test_ok();
        BOUNDED_CHAIN_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_CHAIN_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_EVENT_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_EVENT_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_enforces_exact_fork_depth_before_chain_growth() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let mut timelines = vec![root];
        for depth in 1..=65 {
            let parent = timelines.last().test_ok();
            let child = store
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .test_ok();
            timelines.push(child);
        }
        let bounds = EventReadBounds::new(1, 1, 64, usize::MAX);

        assert!(store
            .read_bounded(timelines[64].id(), SeqRange::all(), bounds)
            .test_ok()
            .is_empty());
        let error = store
            .read_bounded(timelines[65].id(), SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_seeks_late_across_forks_and_fetches_only_the_page() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<_> = (0..4_096).map(|_| make_draft(entity, b"x")).collect();
        store.append(root.id(), &drafts).test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(4_096), "child")
            .test_ok();
        store
            .append(
                child.id(),
                &[make_draft(entity, b"y"), make_draft(entity, b"z")],
            )
            .test_ok();
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 4);

        BOUNDED_EVENTS_EXAMINED.with(|count| count.set(0));
        let page = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_095)), bounds)
            .test_ok();
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
            .test_ok();
        assert_eq!(exhausted.len(), 1);
        assert_eq!(exhausted[0].seq.as_u64(), 4_098);
        BOUNDED_EVENTS_EXAMINED.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_fails_closed_when_memory_sequence_metadata_is_corrupt() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("corrupt").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[make_draft(entity, b"a"), make_draft(entity, b"b")],
            )
            .test_ok();
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .events
            .remove(0);

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .test_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut interior_store = MemoryStore::new();
        let timeline = interior_store.create_timeline("interior").test_ok();
        interior_store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .test_ok();
        interior_store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .events[1]
            .seq = Seq::from_u64(99);
        let error = interior_store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .test_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut fork_store = MemoryStore::new();
        let root = fork_store.create_timeline("root").test_ok();
        let child = fork_store.fork(root.id(), Seq::ZERO, "child").test_ok();
        fork_store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::from_u64(1)));
        let error = fork_store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, usize::MAX, 1, 1),
            )
            .test_err();
        assert!(error.to_string().contains("Fork point exceeds"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_root_count_ignores_many_children_and_caps_at_maximum_plus_one() {
        let mut store = MemoryStore::new();
        let first = store.create_timeline("first").test_ok();
        for index in 0..256 {
            store
                .fork(first.id(), Seq::ZERO, &format!("child-{index}"))
                .test_ok();
        }
        store.create_timeline("second").test_ok();

        assert_eq!(store.root_timeline_count_bounded(0).test_ok(), 1);
        assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(10).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(usize::MAX).test_ok(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_is_opaque_and_unchanged() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store.append(tl.id(), &[make_draft(entity, &raw)]).test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_is_monotonically_increasing() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..10).map(|i| make_draft(entity, &[i])).collect();
        let committed = store.append(tl.id(), &drafts).test_ok();
        for (i, e) in committed.iter().enumerate() {
            assert_eq!(e.seq.as_u64(), (i + 1) as u64);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_range_filters_correctly() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).test_ok();

        let events = store
            .read(
                tl.id(),
                SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)),
            )
            .test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), &[1u8]);
        assert_eq!(events[2].payload.as_slice(), &[3u8]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_is_copy_on_write_child_events_do_not_affect_parent() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();

        // Append 3 events to parent
        let parent_drafts = vec![
            make_draft(entity, b"p1"),
            make_draft(entity, b"p2"),
            make_draft(entity, b"p3"),
        ];
        store.append(tl.id(), &parent_drafts).test_ok();

        // Fork at seq 2
        let child = store.fork(tl.id(), Seq::from_u64(2), "child").test_ok();

        // Append to child
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        // Parent still has only 3 events
        let parent_events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(parent_events.len(), 3);

        // Child sees parent[0..2] + its own events = 3 total
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert_eq!(child_events.len(), 3);
        assert_eq!(child_events[0].payload.as_slice(), b"p1");
        assert_eq!(child_events[1].payload.as_slice(), b"p2");
        assert_eq!(child_events[2].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_forks_expose_one_logical_sequence() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();
        let child_event = store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(child.head, Seq::ZERO);
        assert_eq!(child_event.seq, Seq::from_u64(3));
        assert_eq!(store.logical_head(child.id()).test_ok(), Seq::from_u64(3));

        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();
        let grandchild_event = store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(grandchild_event.seq, Seq::from_u64(4));
        assert_eq!(
            store.logical_head(grandchild.id()).test_ok(),
            Seq::from_u64(4)
        );
        assert_eq!(
            store
                .read(grandchild.id(), SeqRange::all())
                .test_ok()
                .iter()
                .map(|event| (event.seq, event.payload.as_slice()))
                .collect::<Vec<_>>(),
            vec![
                (Seq::from_u64(1), b"r1".as_slice()),
                (Seq::from_u64(2), b"r2".as_slice()),
                (Seq::from_u64(3), b"c1".as_slice()),
                (Seq::from_u64(4), b"g1".as_slice()),
            ]
        );
        assert_eq!(
            store
                .read_event_by_id(grandchild.id(), grandchild_event.id)
                .test_ok()
                .test_ok()
                .seq,
            Seq::from_u64(4)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn logical_sequence_integrity_failures_are_fail_closed() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("integrity-root").test_ok();
        let entity = EntityId::new();
        let event = store
            .append(root.id(), &[make_draft(entity, b"root")])
            .test_ok()
            .pop()
            .test_ok();
        assert!(matches!(
            MemoryStore::logical_event(u64::MAX, event),
            Err(CoreError::Storage(_))
        ));
        assert!(matches!(
            store.chain_hash_at(root.id(), Seq::from_u64(2)),
            Err(CoreError::ForkBeyondHead { .. })
        ));

        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let missing_prefix = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: Vec::new(),
        };
        assert!(matches!(
            missing_prefix.segment_prefix(1),
            Err(CoreError::Storage(_))
        ));

        store.timelines.get_mut(&child.id()).test_ok().timeline.head = Seq::from_u64(1);
        let preceding = ForkChain {
            timelines: vec![root.id(), child.id(), TimelineId::new()],
            fork_seqs: vec![Seq::from_u64(1), Seq::ZERO],
        };
        assert!(matches!(
            preceding.segment_length(&store, 1, child.id()),
            Err(CoreError::Storage(_))
        ));
        let exceeding = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: vec![Seq::from_u64(2)],
        };
        assert!(matches!(
            exceeding.segment_length(&store, 0, root.id()),
            Err(CoreError::Storage(_))
        ));

        store.timelines.get_mut(&root.id()).test_ok().timeline.head = Seq::from_u64(u64::MAX);
        let child_state = store.timelines.get_mut(&child.id()).test_ok();
        child_state.timeline.meta.fork_point = Some((root.id(), Seq::from_u64(u64::MAX)));
        child_state.timeline.head = Seq::from_u64(1);
        assert!(matches!(
            store.logical_head(child.id()),
            Err(CoreError::Storage(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_segment_integrity_failures_are_fail_closed() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("bounded-root").test_ok();
        let child = store.fork(root.id(), Seq::ZERO, "bounded-child").test_ok();
        let chain = vec![root.id(), child.id()];

        store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::ZERO));
        assert!(matches!(
            store.bounded_segment_length(&chain, 0, root.id(), 1),
            Err(CoreError::Storage(_))
        ));

        store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::from_u64(1)));
        assert!(matches!(
            store.bounded_segment_length(&chain, 0, root.id(), 0),
            Err(CoreError::Storage(_))
        ));

        assert!(store.read_event_by_id(child.id(), EventId::new()).is_err());
        assert!(store.read(child.id(), SeqRange::all()).is_err());
        assert!(store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(usize::MAX, usize::MAX, 16, 16),
            )
            .is_err());
        assert!(store.logical_head(child.id()).is_err());
        assert!(store.chain_hash_at(child.id(), Seq::ZERO).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_events_after_fork_point_invisible_to_child() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();

        store
            .append(tl.id(), &[make_draft(entity, b"before")])
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();

        // Append to parent AFTER fork
        store
            .append(tl.id(), &[make_draft(entity, b"after-fork")])
            .test_ok();

        // Child should NOT see "after-fork"
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert!(!child_events
            .iter()
            .any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_returns_error() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
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
    fn bounded_append_is_all_or_nothing_at_the_owned_event_ceiling() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("bounded").test_ok();
        let entity = EntityId::new();
        let two_drafts = [make_draft(entity, b"one"), make_draft(entity, b"two")];

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::ZERO
        );
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let exact_fit = store
            .append_bounded(timeline.id(), &two_drafts, 2)
            .test_ok()
            .test_ok();
        assert_eq!(exact_fit.len(), 2);
        assert_eq!(exact_fit[0].seq, Seq::from_u64(1));
        assert_eq!(exact_fit[1].seq, Seq::from_u64(2));

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 3)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );
        assert_eq!(
            store
                .read_own(timeline.id(), SeqRange::all())
                .test_ok()
                .len(),
            2
        );

        let empty = store
            .append_bounded(timeline.id(), &[], 2)
            .test_ok()
            .test_ok();
        assert!(empty.is_empty());
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );

        let fork = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-fork")
            .test_ok();
        let fork_event = store
            .append_bounded(fork.id(), &[make_draft(entity, b"fork")], 1)
            .test_ok()
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(fork_event.seq, Seq::from_u64(3));
        assert_eq!(
            store
                .append_bounded(fork.id(), &[make_draft(entity, b"too-many")], 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.read_own(fork.id(), SeqRange::all()).test_ok().len(),
            1
        );

        let overflow_fork = store
            .fork(timeline.id(), Seq::from_u64(2), "overflow-fork")
            .test_ok();
        store
            .timelines
            .get_mut(&overflow_fork.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((timeline.id(), Seq::from_u64(u64::MAX)));
        assert!(matches!(
            store.append_bounded(overflow_fork.id(), &[make_draft(entity, b"overflow")], 1,),
            Err(CoreError::Storage(_))
        ));
        assert_eq!(
            store
                .get_timeline(overflow_fork.id())
                .test_ok()
                .test_ok()
                .head,
            Seq::ZERO
        );
        assert!(store
            .read_own(overflow_fork.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_append_rejects_an_owned_head_overflow_before_mutation() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("overflow-head").test_ok();
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .timeline
            .head = Seq::from_u64(u64::MAX);

        assert!(matches!(
            store.append_bounded(
                timeline.id(),
                &[make_draft(EntityId::new(), b"owned-head-overflow")],
                u64::MAX,
            ),
            Err(CoreError::Storage(_))
        ));
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_returns_all() {
        let mut store = MemoryStore::new();
        store.create_timeline("a").test_ok();
        store.create_timeline("b").test_ok();
        store.create_timeline("c").test_ok();
        let list = store.list_timelines().test_ok();
        assert_eq!(list.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_is_deterministic() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).test_ok();

        let r1 = store.read(tl.id(), SeqRange::all()).test_ok();
        let r2 = store.read(tl.id(), SeqRange::all()).test_ok();
        let ids1: Vec<_> = r1.iter().map(|e| e.id).collect();
        let ids2: Vec<_> = r2.iter().map(|e| e.id).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_batch_append_returns_empty() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let result = store.append(tl.id(), &[]).test_ok();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_at_zero_has_empty_parent_events() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"after")])
            .test_ok();
        let child = store.fork(tl.id(), Seq::ZERO, "empty-fork").test_ok();
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert!(child_events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explicit_wall_time_is_preserved() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(123_456_789);
        let draft = make_draft(entity, b"pinned").with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn absent_wall_time_yields_nonzero_timestamp() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let draft = make_draft(entity, b"no-wall-time");
        // wall_time is None — store must call WallTime::now(), which is >0 on any real system.
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert!(committed[0].wall_time.as_micros() > 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_store_default_equals_new() {
        // Exercises MemoryStore::default()
        let store: MemoryStore = MemoryStore::default();
        // A fresh default store has no timelines.
        let list = store.list_timelines().test_ok();
        assert!(list.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at for multi-level fork (parent timeline branch).
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
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
            .test_ok();

        // Fork root at seq 2 to get child.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();

        // Append 2 events to child.
        store
            .append(
                child.id(),
                &[make_draft(entity, b"c1"), make_draft(entity, b"c2")],
            )
            .test_ok();

        // Fork child at logical seq 3 (r1, r2, c1) to get grandchild.
        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();

        // Append to grandchild.
        store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok();

        // Grandchild logical view: r1, r2 (from root up to fork 2),
        // then c1 (from child up to fork 1), then g1.
        let events = store.read(grandchild.id(), SeqRange::all()).test_ok();
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
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store.test_remove_timeline(root.id());
        let err = store.read(child.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_ancestor_metadata_removed() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store.test_remove_timeline(root.id());
        let err = store.fork(child.id(), Seq::ZERO, "grandchild").test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_cyclic_fork_ancestry() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("cycle").test_ok();
        store.test_corrupt(TestCorruption::ForkParent {
            timeline: timeline.id(),
            parent: timeline.id(),
            fork_seq: Seq::ZERO,
        });

        let error = store.read(timeline.id(), SeqRange::all()).test_err();
        assert!(error.to_string().contains("fork ancestry contains a cycle"));
        let bounded_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .test_err();
        assert!(bounded_error
            .to_string()
            .contains("fork ancestry contains a cycle"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_corruption_rejects_a_missing_timeline_target() {
        let mut store = MemoryStore::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.test_corrupt(TestCorruption::ForkParent {
                timeline: TimelineId::new(),
                parent: TimelineId::new(),
                fork_seq: Seq::ZERO,
            });
        }));
        assert!(result.is_err());
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
            .test_err();
        assert!(bounded_error.to_string().contains("timeline not found"));
    }

    #[test]
    fn bounded_chain_rejects_a_missing_ancestor() {
        let mut store = MemoryStore::new();
        let parent = store.create_timeline("parent").test_ok();
        let child = store.fork(parent.id(), Seq::ZERO, "child").test_ok();
        store.test_remove_timeline(parent.id());

        let error = store
            .collect_events_in_range_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .test_err();
        assert!(error
            .to_string()
            .contains(&format!("timeline not found: {}", parent.id())));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multiple_forks_from_same_parent_are_independent() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"shared")])
            .test_ok();

        let branch_a = store.fork(tl.id(), Seq::from_u64(1), "a").test_ok();
        let branch_b = store.fork(tl.id(), Seq::from_u64(1), "b").test_ok();

        store
            .append(branch_a.id(), &[make_draft(entity, b"a-only")])
            .test_ok();
        store
            .append(branch_b.id(), &[make_draft(entity, b"b-only")])
            .test_ok();

        let a_events = store.read(branch_a.id(), SeqRange::all()).test_ok();
        let b_events = store.read(branch_b.id(), SeqRange::all()).test_ok();

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
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let committed = src
            .append(
                tl.id(),
                &[make_draft(entity, b"one"), make_draft(entity, b"two")],
            )
            .test_ok();
        let export = export_timeline(&src, tl.id()).test_ok();
        let original_tl_id = tl.id();
        let original_event_ids: Vec<_> = committed.iter().map(|e| e.id).collect();

        let mut dst = MemoryStore::new();
        let imported = import_timeline_with_id(&mut dst, export).test_ok();
        assert_eq!(imported.id(), original_tl_id);
        let events = dst.read(original_tl_id, SeqRange::all()).test_ok();
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
        let root = store.create_timeline("root").test_ok();
        let err = store.create_timeline_with_meta(root.meta).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "orphan");
        let err = store.create_timeline_with_meta(orphan).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fork_uses_parent_chain() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .test_ok();
        let child_meta = TimelineMeta {
            id: TimelineId::new(),
            mode: pos_core::timeline::TimelineMode::Historical,
            name: Some("child".to_owned()),
            owner: None,
            fork_point: Some((root.id(), Seq::from_u64(1))),
        };
        let child = store.create_timeline_with_meta(child_meta).test_ok();
        assert!(child.meta.fork_point.is_some());
        store.append_committed(child.id(), &[]).test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_is_atomic_on_mid_batch_failure() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let good = store
            .append(tl.id(), &[make_draft(entity, b"ok")])
            .test_ok()
            .remove(0);

        let mut bad = good.clone();
        bad.id = EventId::new();
        bad.seq = Seq::from_u64(2);
        bad.payload = CanonicalBytes::from_vec(b"bad".to_vec());
        bad.payload_hash = pos_core::Hash::from_bytes([9u8; 32]); // mismatch

        let mut later = good;
        later.id = EventId::new();
        later.seq = Seq::from_u64(3);
        later.payload = CanonicalBytes::from_vec(b"later".to_vec());
        later.payload_hash = pos_crypto::chain::hash_payload(&later.payload);

        let err = store.append_committed(tl.id(), &[bad, later]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // No partial apply: still only the originally appended event.
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"ok");
        assert_eq!(
            store.get_timeline(tl.id()).test_ok().test_ok().head,
            Seq::from_u64(1)
        );
    }

    #[test]
    fn delete_timeline_removes_events_and_blocks_with_forks() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();

        let err = store.delete_timeline(root.id()).test_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&CoreError::Storage(String::new()))
        );

        store.delete_timeline(child.id()).test_ok();
        store.delete_timeline(root.id()).test_ok();
        assert_eq!(store.get_timeline(root.id()).test_ok(), None);
        let err = store.delete_timeline(root.id()).test_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&CoreError::TimelineNotFound(TimelineId::new()))
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rolls_back_create_on_append_fail() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let mut committed = src.append(tl.id(), &[make_draft(entity, b"one")]).test_ok();
        let export = export_timeline(&src, tl.id()).test_ok();
        // Corrupt payload hash so append_committed fails after create.
        let mut bad_export = export;
        bad_export.events[0].payload_hash = pos_core::Hash::from_bytes([1u8; 32]);

        let mut dst = MemoryStore::new();
        let err = import_timeline_with_id(&mut dst, bad_export).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(dst.get_timeline(tl.id()).test_ok().is_none());
        let _ = committed.remove(0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_validates_seq_and_payload_hash() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);

        // Empty committed append is ok.
        store.append_committed(tl.id(), &[]).test_ok();

        // Collision with existing head (not contiguous — expects head+1).
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Missing timeline.
        let err = store
            .append_committed(TimelineId::new(), &[good.clone()])
            .test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        // Bad payload hash.
        good.seq = Seq::from_u64(2);
        good.payload_hash = pos_core::Hash::from_bytes([9u8; 32]);
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // Seq gap rejected.
        good.seq = Seq::from_u64(3);
        good.payload_hash = pos_crypto::chain::hash_payload(&good.payload);
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Seq 0 rejected.
        good.seq = Seq::ZERO;
        let err = store.append_committed(tl.id(), &[good]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_event_id() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .test_ok()
            .remove(0);

        let mut dup = first;
        dup.seq = Seq::from_u64(2);
        dup.payload = CanonicalBytes::from_vec(b"b".to_vec());
        dup.payload_hash = pos_crypto::chain::hash_payload(&dup.payload);
        // same EventId as first
        let err = store.append_committed(tl.id(), &[dup]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_id_in_batch() {
        let mut store = MemoryStore::new();
        let tl = store.create_timeline("t").test_ok();
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
                signature_identity: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            }
        };
        let err = store
            .append_committed(tl.id(), &[mk(1, b"a"), mk(2, b"b")])
            .test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    fn generic_committed_geographic_events_are_rejected() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("geo").test_ok();
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
            signature_identity: None,
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
        assert_eq!(
            store.read(timeline.id(), SeqRange::all()).test_ok().len(),
            1
        );
    }

    #[test]
    fn read_event_by_id_fails_closed_for_unknown_timeline() {
        let store = MemoryStore::new();
        assert!(store
            .read_event_by_id(TimelineId::new(), EventId::new())
            .test_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn read_own_helper_returns_matching_event() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("read-own-helper").test_ok();
        store
            .append(
                timeline.id(),
                &[
                    make_draft(EntityId::new(), b"matching-event"),
                    make_draft(EntityId::new(), b"excluded-event"),
                ],
            )
            .test_ok();

        let events = read_own(
            &store,
            timeline.id(),
            SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
        )
        .test_ok();
        assert_eq!(events.len(), 1);

        let all_events = read_own(&store, timeline.id(), SeqRange::all()).test_ok();
        assert_eq!(all_events.len(), 2);
    }

    #[test]
    fn child_reads_do_not_include_parent_events_after_a_fork_point() {
        let mut store = MemoryStore::new();
        let parent = store.create_timeline("lookup-parent").test_ok();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"before-fork")])
            .test_ok();
        let child = store
            .fork(parent.id(), Seq::from_u64(1), "lookup-child")
            .test_ok();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"after-fork")])
            .test_ok();

        assert_eq!(store.read(child.id(), SeqRange::all()).test_ok().len(), 1);
    }

    #[test]
    fn delete_timeline_helper_removes_append_identity() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("delete-helper").test_ok();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"identified-event"));
        store
            .append_intent_or_duplicate(timeline.id(), append_identity(17, 17), intent)
            .test_ok();

        let retained_timeline = store.create_timeline("retained-identity").test_ok();
        let retained = AppendIntent::new(&make_draft(EntityId::new(), b"retained-event"));
        store
            .append_intent_or_duplicate(retained_timeline.id(), append_identity(18, 18), retained)
            .test_ok();

        store
            .fork(retained_timeline.id(), Seq::ZERO, "retained-child")
            .test_ok();

        delete_timeline(&mut store, timeline.id()).test_ok();
        assert_eq!(store.append_identities.len(), 1);
    }

    #[test]
    fn delete_timeline_helper_handles_an_empty_identity_map() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("delete-empty-identities").test_ok();

        delete_timeline(&mut store, timeline.id()).test_ok();

        assert!(store.append_identities.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mutable_state_lookup_rejects_an_unknown_timeline() {
        let mut store = MemoryStore::new();
        assert!(mutable_state(&mut store.timelines, TimelineId::new()).is_err());
        assert!(store.state_mut(TimelineId::new()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_own_fork_roundtrip_preserves_cow() {
        use pos_core::store::{
            export_timeline, export_timeline_own, export_timeline_raw, import_timeline_with_id,
        };

        let mut src = MemoryStore::new();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        // Logical export flattens fork meta.
        let logical = export_timeline(&src, child.id()).test_ok();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.events.len(), 2); // parent[..1] + child

        // Own export keeps CoW shape (`_raw` is a legacy alias of `_own`).
        let own = export_timeline_own(&src, child.id()).test_ok();
        let raw_alias = export_timeline_raw(&src, child.id()).test_ok();
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
        let parent_export = export_timeline_own(&src, root.id()).test_ok();
        import_timeline_with_id(&mut dst, parent_export).test_ok();
        let imported = import_timeline_with_id(&mut dst, own).test_ok();
        assert_eq!(imported.id(), child.id());
        assert!(imported.meta.fork_point.is_some());
        let stitched = dst.read(child.id(), SeqRange::all()).test_ok();
        assert_eq!(stitched.len(), 2);
        assert_eq!(stitched[0].payload.as_slice(), b"p1");
        assert_eq!(stitched[1].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_skips_parent_events() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();
        let own = store.read_own(child.id(), SeqRange::all()).test_ok();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].payload.as_slice(), b"c1");
        let missing = store
            .read_own(TimelineId::new(), SeqRange::all())
            .test_err();
        assert!(matches!(missing, CoreError::TimelineNotFound(_)));

        let bounded = store
            .read_own(
                child.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
            )
            .test_ok();
        assert_eq!(bounded.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_fork_beyond_head() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let mut meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(9), "bad");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).test_err();
        assert!(matches!(err, CoreError::ForkBeyondHead { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_fork_chain_hash_ignores_parent_events_after_fork() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[make_draft(entity, b"r1"), make_draft(entity, b"r2")],
            )
            .test_ok();
        let mid = store.fork(root.id(), Seq::from_u64(1), "mid").test_ok();
        store
            .append(mid.id(), &[make_draft(entity, b"m1")])
            .test_ok();
        // Parent continues after fork — must not affect mid/leaf chain heads.
        store
            .append(root.id(), &[make_draft(entity, b"r3")])
            .test_ok();

        let mut leaf_meta = TimelineMeta::forked_from(mid.id(), Seq::from_u64(2), "leaf");
        leaf_meta.id = TimelineId::new();
        let leaf = store.create_timeline_with_meta(leaf_meta).test_ok();

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
            signature_identity: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        store.append_committed(leaf.id(), &[ev]).test_ok();
        let stitched = store.read(leaf.id(), SeqRange::all()).test_ok();
        // leaf @ logical mid:2 → r1 + m1 + leaf l1; root's post-fork r3 stays invisible.
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
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        let logical = export_timeline(&src, child.id()).test_ok();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.timeline.head, Seq::from_u64(2));
        let parent_ids: std::collections::HashSet<_> = src
            .read_own(root.id(), SeqRange::all())
            .test_ok()
            .into_iter()
            .map(|e| e.id)
            .collect();
        for e in &logical.events {
            assert!(!parent_ids.contains(&e.id));
        }

        let mut dst = MemoryStore::new();
        import_timeline_with_id(&mut dst, export_timeline(&src, root.id()).test_ok()).test_ok();
        // Flattened child import must not collide with parent EventIds.
        import_timeline_with_id(&mut dst, logical).test_ok();
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
        let err = store.create_timeline_with_meta(child_meta).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_rejects_fork_parent_chain_hash_mismatch() {
        use pos_core::store::{export_timeline_own, import_timeline_with_id};

        let mut src = MemoryStore::new();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();

        let mut dst = MemoryStore::new();
        // Divergent parent with same id but different payload.
        let mut parent_export = export_timeline_own(&src, root.id()).test_ok();
        parent_export.events[0].payload = CanonicalBytes::from_vec(b"OTHER".to_vec());
        parent_export.events[0].payload_hash =
            pos_crypto::chain::hash_payload(&parent_export.events[0].payload);
        import_timeline_with_id(&mut dst, parent_export).test_ok();

        let child_export = export_timeline_own(&src, child.id()).test_ok();
        assert!(child_export.parent_fork_hash.is_some());
        let err = import_timeline_with_id(&mut dst, child_export).test_err();
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
        let parent = store.create_timeline("root").test_ok();
        let mut meta = TimelineMeta::forked_from(parent.id(), Seq::ZERO, "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::zero()),
        };
        let err = import_timeline_with_id(&mut store, export).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("chain lookup")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_hasher_uses_custom_hasher() {
        let mut store = MemoryStore::with_hasher(Box::new(pos_crypto::chain::Blake3Hasher));
        let tl = store.create_timeline("hasher-test").test_ok();
        let entity = EntityId::new();
        let drafts = [make_draft(entity, b"payload")];
        let events = store.append(tl.id(), &drafts).test_ok();
        assert_eq!(events.len(), 1);
        assert!(!events[0].payload_hash.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_boundary_rejects_non_v1_serialized_draft() {
        let draft = make_draft(EntityId::new(), b"payload");
        let mut encoded = serde_json::to_value(draft).test_ok();
        encoded["schema_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<EventDraft>(encoded).is_err());
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;
    use pos_core::ConsentAuthority;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T: std::fmt::Debug, E: std::fmt::Debug>(value: Result<T, E>) {
        assert!(
            value.is_err(),
            "expected a rejected coverage value: {value:?}"
        );
        std::mem::drop(value);
    }

    fn draft(payload: &'static [u8]) -> EventDraft {
        EventDraft::new(
            pos_core::EntityId::new(),
            Kind::new("coverage.event"),
            pos_core::CanonicalBytes::from_static(payload),
        )
    }

    fn keyed_draft(key: u8) -> EventDraft {
        EventDraft::new(
            pos_core::EntityId::new(),
            Kind::new("coverage.event"),
            pos_core::CanonicalBytes::from_vec(vec![key]),
        )
    }

    fn identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[test]
    fn memory_error_and_fork_boundaries_are_instrumented() {
        let mut store = MemoryStore::new();
        let root = ok(store.create_timeline("coverage-root"));
        let first = ok(store.append_or_duplicate(
            root.id(),
            identity(1, 1),
            WallTime::from_micros(1),
            draft(b"first"),
        ));
        let second = ok(store.create_timeline("coverage-second"));
        let conflict = ok(store.append_or_duplicate(
            second.id(),
            identity(1, 1),
            WallTime::from_micros(1),
            draft(b"second"),
        ));
        drop((first, conflict));
        expect_err(store.revoke_owntracks_enrollment());
        expect_err(store.logical_head(pos_core::TimelineId::new()));
        expect_err(store.fork(root.id(), Seq::from_u64(2), "beyond"));
        let child = ok(store.fork(root.id(), Seq::ZERO, "child"));
        let _ = ok(store.compute_chain_hash_at(root.id(), Seq::ZERO));
        expect_err(store.compute_chain_hash_at(child.id(), Seq::from_u64(1)));
        store.test_corrupt(TestCorruption::ForkParent {
            timeline: child.id(),
            parent: pos_core::TimelineId::new(),
            fork_seq: Seq::ZERO,
        });
        expect_err(store.read(child.id(), SeqRange::all()));
        expect_err(store.read_event_by_id(child.id(), EventId::new()));

        let malformed_chain = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: Vec::new(),
        };
        expect_err(malformed_chain.segment_length(&store, 1, child.id()));
        expect_err(store.append_or_duplicate_with_limit_visible(
            TimelineId::new(),
            identity(3, 3),
            WallTime::from_micros(2),
            &draft(b"missing-visible"),
            None,
        ));
        expect_err(store.append_visible(TimelineId::new(), &[draft(b"missing-visible")]));

        let protected = ok(store.create_timeline("coverage-protected"));
        ok(
            store.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                protected.id(),
                pos_core::EntityId::new(),
                pos_core::GeoLocationAdmissionFenceV1::new(
                    1,
                    ([1; 32], 1, [2; 32]),
                    (1, false, u64::MAX - 1),
                ),
                [42; 32],
            )),
        );
        ok(store.delete_timeline(protected.id()));

        let admitted = ok(store.create_timeline("coverage-admission"));
        let admitted_entity = pos_core::EntityId::new();
        let fence =
            pos_core::GeoLocationAdmissionFenceV1::new(7, ([3; 32], 8, [4; 32]), (1, false, 1));
        ok(
            store.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                admitted.id(),
                admitted_entity,
                fence,
                [43; 32],
            )),
        );
        store.test_remove_timeline(admitted.id());
        let request = pos_core::geo_admission::GeoLocationAdmissionRequestV1::from_input(
            pos_core::geo_admission::GeoLocationAdmissionInputV1::new(
                admitted.id(),
                admitted_entity,
                pos_core::CanonicalBytes::from_static(b"missing-state"),
                7,
                ([3; 32], 8, [4; 32]),
                (1, false, 2),
                ([5; 32], [6; 32]),
            ),
        );
        expect_err(store.admit_geo_location(request));
    }

    #[test]
    fn memory_append_and_bounded_read_boundaries_are_instrumented() {
        let mut store = MemoryStore::new();
        let timeline = ok(store.create_timeline("coverage-append"));
        expect_err(store.append(pos_core::TimelineId::new(), &[draft(b"missing")]));
        let _ = ok(store.append(timeline.id(), &[draft(b"present")]));
        let bounds = EventReadBounds::new(1024, usize::MAX, usize::MAX, 1_000_000);
        let _ = ok(store.read_bounded(timeline.id(), SeqRange::all(), bounds));
        let _ = ok(store.append_bounded(timeline.id(), &[draft(b"too-many")], 1));
    }

    #[test]
    fn consent_append_rejects_a_missing_permit_after_authority_binding() {
        let mut store = MemoryStore::new();
        let timeline = ok(store.create_timeline("coverage-missing-permit"));
        let authority = ConsentAuthority::new();
        ok(store.bind_consent_authority(authority.append_permit()));
        expect_err(store.append_bounded_with_boundary(timeline.id(), &[], 10, true, None, None));
    }

    #[test]
    fn consent_revocation_and_cleanup_boundaries_are_instrumented() {
        let mut store = MemoryStore::new();
        let timeline = ok(store.create_timeline("coverage-revocation"));
        let subject = pos_core::EntityId::new();
        let revocation = pos_core::ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: pos_core::EntityId::new(),
            grant_seq: 1,
            fence_seq: 1,
        };
        let draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok(revocation.encode()),
        );
        let authority = ConsentAuthority::new();
        let permit = authority.append_permit();
        ok(store.bind_consent_authority(permit));
        let consent_scope = AppendDedupScope::from_keyed_hash([101; 32]);
        let appended = ok(store.append_consent_revocation_bounded(
            timeline.id(),
            std::slice::from_ref(&draft),
            permit,
            1,
            consent_scope,
        ));
        assert_eq!(appended.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            ok(store.pending_append_identity_cleanup()),
            Some(consent_scope)
        );
        assert_eq!(ok(store.remove_append_identities(consent_scope)), 0);
        assert_eq!(ok(store.pending_append_identity_cleanup()), None);

        let ordinary = ok(store.create_timeline("coverage-cleanup"));
        let identity_scope = AppendDedupScope::from_keyed_hash([102; 32]);
        for key in [103, 104] {
            ok(store.append_or_duplicate(
                ordinary.id(),
                AppendIdentity::new(AppendDedupKey::from_keyed_hash([key; 32]), identity_scope),
                WallTime::from_micros(1),
                keyed_draft(key),
            ));
        }
        let first =
            ok(store.remove_append_identities_bounded(identity_scope, std::num::NonZeroUsize::MIN));
        assert!(first.more_may_remain);
        assert_eq!(
            ok(store.pending_append_identity_cleanup()),
            Some(identity_scope)
        );
        let second =
            ok(store.remove_append_identities_bounded(identity_scope, std::num::NonZeroUsize::MIN));
        assert!(!second.more_may_remain);
        assert_eq!(ok(store.pending_append_identity_cleanup()), None);
    }
}
