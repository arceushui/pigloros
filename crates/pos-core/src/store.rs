//! Event store port and timeline export/import helpers.
//!
//! # Which export / import path?
//!
//! | Intent | Export | Import | Notes |
//! |--------|--------|--------|-------|
//! | Independent clone | [`export_timeline`] | [`import_timeline`] | Remints timeline/event ids; converts to drafts (signatures dropped) |
//! | Identity `CoW` | [`export_timeline_own`] | [`import_timeline_with_id`] | Parent first, then child; forks need `parent_fork_hash` |
//! | Verified identity | [`export_timeline_own`] | `pos_store::import_timeline_with_verified_signatures` | Every event must be signed under one key |
//!
//! Prefer [`export_timeline_own`] (alias: [`export_timeline_cow`]) for copy-on-write sync.
//! [`export_timeline_raw`] is the same function kept for existing call sites.
//!
//! # `CoW` sync order
//!
//! 1. `export_timeline_own(src, root)` → `import_timeline_with_id(dst, …)`
//! 2. `export_timeline_own(src, child)` → `import_timeline_with_id(dst, …)`
//!
//! Importing a forked child before its parent fails (`TimelineNotFound`).

use crate::{
    clock::{Seq, WallTime},
    crypto::Hash,
    error::CoreError,
    event::{Event, EventDraft},
    hasher::Hasher,
    ids::{EventId, TimelineId},
    timeline::{Timeline, TimelineMeta},
};

/// Opaque, fixed-size identity for a retried external append.
///
/// An application derives this from its external identity using a keyed hash.
/// The `EventStore` persists only these digest bytes; it never receives the
/// raw message or the deduplication preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AppendDedupKey([u8; 32]);

impl AppendDedupKey {
    #[must_use]
    pub const fn from_keyed_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque, fixed-size scope that owns one or more deduplication identities.
///
/// Applications use this to revoke all removable deduplication state for one
/// external principal without persisting that principal's raw identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AppendDedupScope([u8; 32]);

impl AppendDedupScope {
    #[must_use]
    pub const fn from_keyed_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A deduplication identity and its revocable ownership scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendIdentity {
    pub dedup_key: AppendDedupKey,
    pub scope: AppendDedupScope,
}

impl AppendIdentity {
    #[must_use]
    pub const fn new(dedup_key: AppendDedupKey, scope: AppendDedupScope) -> Self {
        Self { dedup_key, scope }
    }
}

/// The fixed retention horizon for an append identity.
///
/// The horizon is part of the append-or-duplicate storage contract rather
/// than a caller-selected expiry policy.
pub const APPEND_IDENTITY_RETENTION_MICROS: u64 = 7 * 24 * 60 * 60 * 1_000_000;

/// Canonical caller-owned fields used to compare identified retries.
/// Generated Event metadata, including `wall_time`, is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendIntent {
    pub entity: crate::EntityId,
    pub event_type: crate::Kind,
    pub payload: crate::CanonicalBytes,
    pub causation_id: Option<crate::EventId>,
    pub correlation_id: Option<crate::CorrelationId>,
    pub schema_version: crate::SchemaVersion,
}

impl AppendIntent {
    #[must_use]
    pub fn new(draft: &EventDraft) -> Self {
        Self {
            entity: draft.entity,
            event_type: draft.event_type.clone(),
            payload: draft.payload.clone(),
            causation_id: draft.causation_id,
            correlation_id: draft.correlation_id,
            schema_version: draft.schema_version,
        }
    }

    #[must_use]
    pub fn into_draft(self) -> EventDraft {
        EventDraft {
            entity: self.entity,
            event_type: self.event_type,
            payload: self.payload,
            wall_time: None,
            causation_id: self.causation_id,
            correlation_id: self.correlation_id,
            schema_version: self.schema_version,
        }
    }
}

/// Result of one bounded physical cleanup pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeOutcome {
    pub removed: usize,
    pub more_may_remain: bool,
}

/// Checked seven-day expiry calculation; saturation is forbidden.
///
/// # Errors
/// Returns [`CoreError::Storage`] when the timestamp would overflow.
pub fn checked_append_identity_expires_at(admitted_at: WallTime) -> Result<WallTime, CoreError> {
    admitted_at
        .as_micros()
        .checked_add(APPEND_IDENTITY_RETENTION_MICROS)
        .map(WallTime::from_micros)
        .ok_or_else(|| CoreError::Storage("append identity expiry overflow".to_owned()))
}

/// Return the fixed expiry for an identity admitted at `admitted_at`.
#[must_use]
pub const fn append_identity_expires_at(admitted_at: WallTime) -> WallTime {
    WallTime::from_micros(
        admitted_at
            .as_micros()
            .saturating_add(APPEND_IDENTITY_RETENTION_MICROS),
    )
}

/// Result of atomically appending one externally identified Event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendOrDuplicateOutcome {
    /// The Event was durably appended for the first time.
    Appended(Box<Event>),
    /// The same identity and retained canonical content had already been appended.
    Duplicate { event_id: EventId },
    /// The identity was already used for different retained canonical content.
    Conflict,
}

/// Range of sequence numbers to read.
#[derive(Clone, Copy, Debug)]
pub struct SeqRange {
    pub from: Seq,
    /// Inclusive upper bound. `None` means read to the end.
    pub to: Option<Seq>,
}

/// Work and field bounds applied before Events are cloned or materialised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventReadBounds {
    payload_bytes: usize,
    event_type_bytes: usize,
    fork_depth: usize,
    events: usize,
    total_bytes: usize,
    max_elapsed_micros: u64,
}

impl EventReadBounds {
    #[must_use]
    pub const fn new(
        max_payload_bytes: usize,
        max_event_type_bytes: usize,
        max_fork_depth: usize,
        max_events: usize,
    ) -> Self {
        Self::new_with_total_bytes(
            max_payload_bytes,
            max_event_type_bytes,
            max_fork_depth,
            max_events,
            usize::MAX,
        )
    }

    #[must_use]
    pub const fn new_with_total_bytes(
        max_payload_bytes: usize,
        max_event_type_bytes: usize,
        max_fork_depth: usize,
        max_events: usize,
        max_total_bytes: usize,
    ) -> Self {
        Self {
            payload_bytes: max_payload_bytes,
            event_type_bytes: max_event_type_bytes,
            fork_depth: max_fork_depth,
            events: max_events,
            total_bytes: max_total_bytes,
            max_elapsed_micros: u64::MAX,
        }
    }

    #[must_use]
    pub const fn new_with_total_bytes_and_elapsed(
        max_payload_bytes: usize,
        max_event_type_bytes: usize,
        max_fork_depth: usize,
        max_events: usize,
        max_total_bytes: usize,
        max_elapsed_micros: u64,
    ) -> Self {
        Self {
            payload_bytes: max_payload_bytes,
            event_type_bytes: max_event_type_bytes,
            fork_depth: max_fork_depth,
            events: max_events,
            total_bytes: max_total_bytes,
            max_elapsed_micros,
        }
    }

    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        self.payload_bytes
    }

    #[must_use]
    pub const fn max_event_type_bytes(self) -> usize {
        self.event_type_bytes
    }

    #[must_use]
    pub const fn max_fork_depth(self) -> usize {
        self.fork_depth
    }

    #[must_use]
    pub const fn max_events(self) -> usize {
        self.events
    }

    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.total_bytes
    }

    #[must_use]
    pub const fn with_max_total_bytes(self, max_total_bytes: usize) -> Self {
        Self {
            total_bytes: max_total_bytes,
            ..self
        }
    }

    #[must_use]
    pub const fn max_elapsed_micros(self) -> u64 {
        self.max_elapsed_micros
    }
}

impl SeqRange {
    #[must_use]
    pub const fn from_seq(from: Seq) -> Self {
        Self { from, to: None }
    }

    #[must_use]
    pub const fn bounded(from: Seq, to: Seq) -> Self {
        Self { from, to: Some(to) }
    }

    #[must_use]
    pub const fn all() -> Self {
        Self {
            from: Seq::ZERO,
            to: None,
        }
    }
}

/// A portable snapshot of a timeline and all its events.
/// Used for export/import across different `EventStore` backends.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimelineExport {
    pub timeline: Timeline,
    pub events: Vec<Event>,
    /// Expected parent hash-chain tip at [`TimelineMeta::fork_point`].
    ///
    /// Set by [`export_timeline_own`] / [`export_timeline_raw`] for forked timelines so
    /// [`import_timeline_with_id`] can reject divergent parent history.
    /// Always `None` for roots and for flattened logical [`export_timeline`] snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_fork_hash: Option<Hash>,
}

/// The kernel's event-store abstraction. Implementations live in `pos-store`.
///
/// All methods are synchronous — no async in the kernel.
/// `Send` is required; `Sync` is not — multi-threaded callers wrap in `Arc<Mutex<_>>`.
///
/// # Provider independence
/// Timeline lifecycle and identity-preserving import go through this trait.
/// Export/import helpers live as free functions alongside the trait so callers can
/// hold `Box<dyn EventStore>` and swap backends without changing call sites.
pub trait EventStore: Send {
    /// Create a new root timeline with the given name.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError>;

    /// Append one or more draft events to a timeline, returning the committed events.
    ///
    /// Batching is required for performance: single-row commit is too slow for `SQLite` WAL.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError>;

    /// Atomically append one externally identified draft or report its prior admission.
    ///
    /// Implementations must persist the opaque identity and Event in the same
    /// transaction, derive the fixed seven-day expiry from `admitted_at`, and
    /// compare retained Event content themselves on a repeated identity. Call
    /// [`Self::purge_expired_append_identities`] from asynchronous maintenance,
    /// never from this admission path.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the backend does not implement
    /// atomic append-or-duplicate, or the same errors as [`Self::append`].
    fn append_or_duplicate(
        &mut self,
        _timeline: TimelineId,
        _identity: AppendIdentity,
        _admitted_at: WallTime,
        _draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        Err(CoreError::Storage(
            "atomic append-or-duplicate is unsupported by this EventStore".to_owned(),
        ))
    }

    /// Append using a canonical intent and the store-owned admission clock.
    ///
    /// # Errors
    /// Returns a backend or clock error when admission cannot be committed.
    fn append_intent_or_duplicate(
        &mut self,
        _timeline: TimelineId,
        _identity: AppendIdentity,
        _intent: AppendIntent,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        Err(CoreError::Storage(
            "store-owned identified append is unsupported by this EventStore".to_owned(),
        ))
    }

    /// Append an identified intent subject to an owned-event ceiling.
    ///
    /// The identity lookup always precedes the ceiling check, so a retry can
    /// recover its original Event even when the Timeline is already full.
    /// `Some` contains the normal append-or-duplicate outcome; `None` means a
    /// new append would exceed `max_owned_events`.
    ///
    /// # Errors
    /// Returns a backend or clock error when admission cannot be committed.
    fn append_intent_or_duplicate_bounded(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        max_owned_events: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let _ = max_owned_events;
        self.append_intent_or_duplicate(timeline, identity, intent)
            .map(Some)
    }

    /// Read one Event by its durable identifier without materialising a
    /// Timeline range. Adapters must override this with an indexed lookup;
    /// the compatibility default reports no retained Event.
    ///
    /// # Errors
    /// Returns the same storage errors as [`Self::read`].
    fn read_event_by_id(
        &self,
        _timeline: TimelineId,
        _event_id: EventId,
    ) -> Result<Option<Event>, CoreError> {
        Ok(None)
    }

    /// Remove at most `limit` expired identities using the store-owned clock.
    ///
    /// # Errors
    /// Returns a backend or clock error when cleanup cannot complete.
    fn purge_expired_append_identities_bounded(
        &mut self,
        _limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        Err(CoreError::Storage(
            "bounded append identity cleanup is unsupported by this EventStore".to_owned(),
        ))
    }

    /// Delete append identities whose fixed retention horizon has passed.
    ///
    /// This maintenance operation is intentionally separate from admission so
    /// normal ingress remains one bounded lookup and one atomic write.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the backend does not implement
    /// append identity cleanup.
    fn purge_expired_append_identities(&mut self, _now: WallTime) -> Result<usize, CoreError> {
        Err(CoreError::Storage(
            "append identity cleanup is unsupported by this EventStore".to_owned(),
        ))
    }

    /// Remove all append identities owned by one revocable opaque scope.
    ///
    /// Applications call this outside the admission path when an external
    /// principal is revoked or withdrawn. It cannot remove Timeline Events.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the backend does not implement
    /// append identity withdrawal cleanup.
    fn remove_append_identities(&mut self, _scope: AppendDedupScope) -> Result<usize, CoreError> {
        Err(CoreError::Storage(
            "append identity withdrawal cleanup is unsupported by this EventStore".to_owned(),
        ))
    }

    /// Read events from a timeline in a seq range.
    ///
    /// For a forked timeline, this transparently stitches `parent[0..fork_seq]` + child events.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError>;

    /// Read events while refusing any selected variable field or aggregate byte
    /// budget outside `bounds`.
    ///
    /// Implementations that support this capability must seek to `range.from`,
    /// examine and materialise no more than [`EventReadBounds::max_events`],
    /// enforce every field bound before materialising that field, and enforce
    /// the Fork-depth bound while walking ancestry rather than after collecting
    /// it. The safe default refuses the operation; it never falls back to
    /// [`Self::read`], because doing so could allocate or scan
    /// attacker-controlled data before checking its bounds.
    ///
    /// # Errors
    /// Returns [`CoreError::PayloadTooLarge`],
    /// [`CoreError::EventMetadataTooLarge`], or
    /// [`CoreError::ReadBytesTooLarge`], or
    /// [`CoreError::ReadTimeTooLarge`], or
    /// [`CoreError::ForkDepthTooLarge`] when a selected request exceeds a
    /// bound; [`CoreError::Storage`] when the adapter does not implement bounded
    /// reads; or the same errors as [`Self::read`].
    fn read_bounded(
        &self,
        _timeline: TimelineId,
        _range: SeqRange,
        _bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        Err(CoreError::Storage(
            "bounded event reads are unsupported by this EventStore".to_owned(),
        ))
    }

    /// Read events stored directly on this timeline (no fork stitching or renumbering).
    ///
    /// Used by [`export_timeline_own`] for identity-preserving fork sync.
    ///
    /// Default: delegates to [`Self::read`] (logical / stitched). Real `CoW` stores must
    /// override this; test stubs may keep the default.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.read(timeline, range)
    }

    /// Create a forked child timeline at `at_seq`.
    ///
    /// The child is copy-on-write: it stores only its own events going forward.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the parent does not exist, or
    /// [`CoreError::ForkBeyondHead`] if `at_seq` exceeds the parent's head.
    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError>;

    /// List all known timelines.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError>;

    /// Count root Timelines, stopping once `maximum + 1` roots are seen.
    ///
    /// Implementations must not clone or materialise Timeline metadata. The
    /// safe default refuses the operation so quota enforcement cannot silently
    /// fall back to [`Self::list_timelines`].
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] if the adapter does not implement the
    /// bounded scalar count or its underlying query fails.
    fn root_timeline_count_bounded(&self, _maximum: usize) -> Result<usize, CoreError> {
        Err(CoreError::Storage(
            "bounded root Timeline counts are unsupported by this EventStore".to_owned(),
        ))
    }

    /// Get a specific timeline's metadata.
    ///
    /// Returns `Ok(None)` if the timeline does not exist.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError>;

    /// Create a timeline using caller-supplied metadata (preserves [`TimelineId`]).
    ///
    /// Required for identity-preserving import across shared-world nodes (Wave 6 / #87).
    ///
    /// Default fails closed so thin test stubs need not implement Wave 6 APIs.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] if the id already exists or the backend cannot
    /// honour the requested identity. Returns [`CoreError::TimelineNotFound`] if a
    /// fork parent is missing. Returns [`CoreError::ForkBeyondHead`] if `fork_point.1`
    /// exceeds the parent's head.
    fn create_timeline_with_meta(&mut self, _meta: TimelineMeta) -> Result<Timeline, CoreError> {
        Err(CoreError::Storage(
            "create_timeline_with_meta not supported by this store".to_owned(),
        ))
    }

    /// Append already-committed events, preserving event ids, seqs, and payload hashes.
    ///
    /// Used by [`import_timeline_with_id`]. Implementations must be all-or-nothing for the
    /// batch (no partial apply on validation failure). Seqs must be contiguous from
    /// `head + 1`, and each [`EventId`] must be unique in the store.
    ///
    /// Default fails closed so thin test stubs need not implement Wave 6 APIs.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist, or
    /// [`CoreError::Storage`] on conflict / validation failure.
    fn append_committed(
        &mut self,
        _timeline: TimelineId,
        _events: &[Event],
    ) -> Result<(), CoreError> {
        Err(CoreError::Storage(
            "append_committed not supported by this store".to_owned(),
        ))
    }

    /// Delete a timeline and its events.
    ///
    /// Used to roll back a failed [`import_timeline_with_id`] after create succeeded.
    ///
    /// Default fails closed so thin test stubs need not implement Wave 6 APIs.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist, or
    /// [`CoreError::Storage`] if the timeline still has dependent forks / I/O failure.
    fn delete_timeline(&mut self, _id: TimelineId) -> Result<(), CoreError> {
        Err(CoreError::Storage(
            "delete_timeline not supported by this store".to_owned(),
        ))
    }

    /// CoW-aware hash-chain value at `at_seq` on `timeline` (inclusive).
    ///
    /// Used by [`export_timeline_own`] / [`import_timeline_with_id`] to bind fork imports
    /// to parent history.
    ///
    /// Default fails closed so thin test stubs need not implement Wave 6 APIs.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline (or an ancestor) is missing,
    /// or [`CoreError::Storage`] if the backend does not support hash chains.
    fn chain_hash_at(&self, _timeline: TimelineId, _at_seq: Seq) -> Result<Hash, CoreError> {
        Err(CoreError::Storage(
            "chain_hash_at not supported by this store".to_owned(),
        ))
    }

    /// Create a timeline and append committed events as one logical import.
    ///
    /// Must roll back a successful create if append or the final fetch fails (via
    /// [`Self::delete_timeline`], or a stronger transactional rollback).
    ///
    /// Default fails closed (object-safe). Prefer overriding with
    /// [`import_committed_with_rollback`] or a transactional backend.
    ///
    /// # Errors
    /// Returns the same classes of error as create/append/get, or a combined rollback error.
    fn import_committed(
        &mut self,
        _meta: TimelineMeta,
        _events: &[Event],
    ) -> Result<Timeline, CoreError> {
        Err(CoreError::Storage(
            "import_committed not supported by this store".to_owned(),
        ))
    }
}

/// Export a timeline's **logical** event stream as a portable snapshot.
///
/// Uses [`EventStore::read`], which stitches parent history into forked children and
/// renumbers seqs. [`Timeline::head`] is rewritten to the logical stream head (last
/// event seq, or zero if empty).
///
/// When the source was a fork, `fork_point` is cleared and every event receives a
/// **fresh** [`EventId`] (causation links remapped within the export; signatures
/// cleared). That yields an independent root that will not collide with parent
/// `EventId`s on import. For `CoW` fork round-trips that must keep `fork_point` and
/// original ids, use [`export_timeline_own`].
///
/// # Errors
/// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
pub fn export_timeline(
    store: &dyn EventStore,
    id: TimelineId,
) -> Result<TimelineExport, CoreError> {
    let mut export =
        export_timeline_using(store.get_timeline(id), store.read(id, SeqRange::all()), id)?;
    let was_fork = export.timeline.meta.fork_point.take().is_some();
    if was_fork {
        materialize_fork_export_as_root(&mut export);
    }
    export.parent_fork_hash = None;
    export.timeline.head = export
        .events
        .last()
        .map_or(crate::clock::Seq::ZERO, |e| e.seq);
    Ok(export)
}

/// Export only events stored on this timeline (no stitch / renumber) — preferred `CoW` name.
///
/// Preserves [`TimelineMeta::fork_point`] so [`import_timeline_with_id`] can recreate
/// a copy-on-write child. **Parent timeline must already exist at the destination.**
/// Records [`TimelineExport::parent_fork_hash`] so the destination can reject a
/// divergent parent history.
///
/// Same implementation as [`export_timeline_raw`] (kept for existing call sites) and
/// [`export_timeline_cow`].
///
/// # Errors
/// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
pub fn export_timeline_own(
    store: &dyn EventStore,
    id: TimelineId,
) -> Result<TimelineExport, CoreError> {
    export_timeline_raw(store, id)
}

/// Alias for [`export_timeline_own`] (copy-on-write / identity-preserving export).
pub use export_timeline_own as export_timeline_cow;

/// Export only events stored on this timeline (no stitch / renumber).
///
/// Prefer [`export_timeline_own`] in new code. This name is retained for existing
/// Wave 6 call sites and means the same thing.
///
/// Preserves [`TimelineMeta::fork_point`] so [`import_timeline_with_id`] can recreate
/// a copy-on-write child. Parent timeline must already exist at the destination.
/// Records [`TimelineExport::parent_fork_hash`] so the destination can reject a
/// divergent parent history.
///
/// # Errors
/// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
pub fn export_timeline_raw(
    store: &dyn EventStore,
    id: TimelineId,
) -> Result<TimelineExport, CoreError> {
    let mut export = export_timeline_using(
        store.get_timeline(id),
        store.read_own(id, SeqRange::all()),
        id,
    )?;
    match export.timeline.meta.fork_point {
        Some((parent, at_seq)) => {
            export.parent_fork_hash = Some(store.chain_hash_at(parent, at_seq)?);
        }
        None => {
            export.parent_fork_hash = None;
        }
    }
    Ok(export)
}

/// Import a previously exported timeline as a **new** logical clone.
///
/// Creates a fresh [`TimelineId`], converts events to [`EventDraft`]s, and appends
/// via [`EventStore::append`] — so **event ids are reminted**, seqs restart from the
/// store, and **signatures are not carried** (`EventDraft` has no signature field).
///
/// For identity-preserving `CoW` sync, use [`export_timeline_own`] +
/// [`import_timeline_with_id`] instead. For crypto-checked identity import, see
/// `pos_store::import_timeline_with_verified_signatures`.
///
/// # Errors
/// Returns a [`CoreError::Storage`] error if the timeline already exists or on I/O failure.
pub fn import_timeline(
    store: &mut dyn EventStore,
    export: TimelineExport,
) -> Result<Timeline, CoreError> {
    let TimelineExport {
        timeline,
        events,
        parent_fork_hash: _,
    } = export;
    let name = timeline.meta.name.unwrap_or_default();
    ensure_import_events_are_non_geographic(&events).and_then(|()| {
        let create_result = store.create_timeline(&name);
        import_timeline_using(create_result, events, |timeline_id, drafts| {
            store.append(timeline_id, drafts)
        })
    })
}

/// Import a timeline snapshot preserving the original [`TimelineId`] and event IDs.
///
/// Requires the backend to implement [`EventStore::create_timeline_with_meta`],
/// [`EventStore::append_committed`], [`EventStore::delete_timeline`], and
/// [`EventStore::chain_hash_at`] (Memory + `SQLite` do; test stubs may not).
///
/// Forked exports must come from [`export_timeline_own`] (own events + `fork_point` +
/// `parent_fork_hash`). Logical [`export_timeline`] snapshots of forks are flattened
/// (no `fork_point`).
///
/// **Import parent before child.** A forked child whose parent is missing at the
/// destination will fail.
///
/// Uses [`EventStore::import_committed`] so backends can apply create+append atomically.
/// The default import rolls back via delete on any failure after create, including a
/// failed final timeline fetch. If rollback delete also fails, the combined error is
/// returned (the id may remain occupied).
///
/// Signatures are persisted as opaque blobs; cryptographic verification is the caller's
/// responsibility (see `pos_crypto::signing::verify_events_all_signed` / store helpers).
/// For mixed unsigned events or multiple signers, call `verify_events` yourself then
/// this function — do not use the all-signed store helper.
///
/// # Errors
/// Returns a [`CoreError::Storage`] error if a timeline with that ID already exists,
/// if the backend returns a different id, if a fork parent is missing / beyond head /
/// hash-mismatched, or on I/O failure.
pub fn import_timeline_with_id(
    store: &mut dyn EventStore,
    export: TimelineExport,
) -> Result<Timeline, CoreError> {
    let TimelineExport {
        timeline,
        events,
        parent_fork_hash,
    } = export;

    ensure_import_events_are_non_geographic(&events).and_then(|()| {
        if let Some((parent, at_seq)) = timeline.meta.fork_point {
            let expected = parent_fork_hash.ok_or_else(|| {
                CoreError::Storage(
                    "forked import requires parent_fork_hash (use export_timeline_own)".to_owned(),
                )
            })?;
            let actual = store.chain_hash_at(parent, at_seq)?;
            if actual != expected {
                return Err(CoreError::Storage(
                    "fork parent chain hash mismatch".to_owned(),
                ));
            }
        }

        store.import_committed(timeline.meta, &events)
    })
}

/// Refuse protected evidence before a generic import creates or mutates a Timeline.
fn ensure_import_events_are_non_geographic(events: &[Event]) -> Result<(), CoreError> {
    if events
        .iter()
        .any(|event| crate::is_geographic_event_type(&event.event_type))
    {
        Err(CoreError::Storage(
            "generic import of geographic evidence is disabled".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Default create→append→fetch import with delete-based rollback.
///
/// Used by [`MemoryStore`](../../../../pos-store) and test stubs. `SQLite` overrides
/// [`EventStore::import_committed`] with a single transaction instead.
///
/// # Errors
/// Returns create/append/get errors, or a combined error when rollback delete fails.
pub fn import_committed_with_rollback(
    store: &mut dyn EventStore,
    meta: TimelineMeta,
    events: &[Event],
) -> Result<Timeline, CoreError> {
    let expected_id = meta.id;
    let created = store.create_timeline_with_meta(meta)?;
    if created.id() != expected_id {
        return Err(rollback_import(
            store,
            created.id(),
            CoreError::Storage("store did not honour requested TimelineId".to_owned()),
        ));
    }
    if let Err(err) = store.append_committed(expected_id, events) {
        return Err(rollback_import(store, expected_id, err));
    }
    match store.get_timeline(expected_id) {
        Ok(Some(tl)) => Ok(tl),
        Ok(None) => Err(rollback_import(
            store,
            expected_id,
            CoreError::TimelineNotFound(expected_id),
        )),
        Err(err) => Err(rollback_import(store, expected_id, err)),
    }
}

/// Delete a partially imported timeline; if delete fails, combine with the original error.
fn rollback_import(store: &mut dyn EventStore, id: TimelineId, err: CoreError) -> CoreError {
    match store.delete_timeline(id) {
        Ok(()) => err,
        Err(del_err) => CoreError::Storage(format!(
            "import failed ({err}); rollback delete also failed ({del_err})"
        )),
    }
}

/// Flatten a forked logical export into an independent root: new event ids, remapped
/// causation, cleared signatures (they bound the old identities).
fn materialize_fork_export_as_root(export: &mut TimelineExport) {
    use crate::ids::EventId;
    use std::collections::HashMap;

    let new_ids: Vec<EventId> = export.events.iter().map(|_| EventId::new()).collect();
    let id_map: HashMap<EventId, EventId> = export
        .events
        .iter()
        .zip(new_ids.iter().copied())
        .map(|(event, new_id)| (event.id, new_id))
        .collect();
    for (event, new_id) in export.events.iter_mut().zip(new_ids) {
        event.id = new_id;
        if let Some(cid) = event.causation_id {
            event.causation_id = id_map.get(&cid).copied();
        }
        event.signature = None;
    }
}

/// Validate a committed-event batch before apply: sort, contiguous seqs from `head+1`,
/// payload-hash integrity via `hasher`, and unique event ids (via `id_is_taken`).
///
/// # Errors
/// Returns [`CoreError::Storage`] when validation fails.
pub fn validate_committed_batch(
    head: Seq,
    events: &[Event],
    id_is_taken: &mut dyn FnMut(&crate::ids::EventId) -> bool,
    hasher: &dyn Hasher,
) -> Result<Vec<Event>, CoreError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let mut ordered = events.to_vec();
    ordered.sort_by_key(|e| e.seq.as_u64());

    let mut expected = head.next();
    let mut seen = std::collections::HashSet::new();
    for event in &ordered {
        if event.seq.as_u64() == 0 {
            return Err(CoreError::Storage(
                "committed event seq must be >= 1".to_owned(),
            ));
        }
        if event.seq != expected {
            return Err(CoreError::Storage(format!(
                "committed event seq {} is not contiguous (expected {})",
                event.seq.as_u64(),
                expected.as_u64()
            )));
        }
        if !seen.insert(event.id) || id_is_taken(&event.id) {
            return Err(CoreError::Storage(format!(
                "duplicate EventId on committed import: {}",
                event.id
            )));
        }
        if hasher.hash_payload(&event.payload) != event.payload_hash {
            return Err(CoreError::Storage(
                "payload_hash mismatch on committed import".to_owned(),
            ));
        }
        expected = expected.next();
    }
    Ok(ordered)
}

fn export_timeline_using(
    timeline_result: Result<Option<Timeline>, CoreError>,
    events_result: Result<Vec<Event>, CoreError>,
    id: TimelineId,
) -> Result<TimelineExport, CoreError> {
    let Some(timeline) = timeline_result? else {
        return Err(CoreError::TimelineNotFound(id));
    };
    let events = events_result?;
    Ok(TimelineExport {
        timeline,
        events,
        parent_fork_hash: None,
    })
}

fn import_timeline_using<A>(
    create_result: Result<Timeline, CoreError>,
    events: Vec<Event>,
    append: A,
) -> Result<Timeline, CoreError>
where
    A: FnOnce(TimelineId, &[EventDraft]) -> Result<Vec<Event>, CoreError>,
{
    let tl = create_result?;
    let drafts: Vec<EventDraft> = events
        .into_iter()
        .map(|e| {
            let mut draft = EventDraft::new(e.entity, e.event_type, e.payload);
            draft.causation_id = e.causation_id;
            draft.correlation_id = e.correlation_id;
            draft.schema_version = e.schema_version;
            draft.wall_time = Some(e.wall_time);
            draft
        })
        .collect();
    append(tl.id(), &drafts)?;
    Ok(tl)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
        timeline::{Timeline, TimelineMeta},
    };

    // The EventStore trait lives here; implementations are in pos-store.
    // These tests verify the trait contract is sound (not that it compiles with an impl).

    /// Minimal in-memory store used only for trait-level tests in pos-core.
    struct TrivialStore {
        counter: u64,
    }

    impl TrivialStore {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    /// Store that fails selected operations for export/import error-path coverage.
    struct FlakyStore {
        mode: FlakyMode,
        counter: u64,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FlakyMode {
        GetTimelineErr,
        GetTimelineMissing,
        ReadErr,
        CreateTimelineErr,
        AppendErr,
        Healthy,
    }

    impl FlakyStore {
        fn new(mode: FlakyMode) -> Self {
            Self { mode, counter: 0 }
        }

        fn healthy_timeline() -> Timeline {
            Timeline::new(TimelineMeta::root("flaky"))
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl EventStore for FlakyStore {
        fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
            if self.mode == FlakyMode::CreateTimelineErr {
                return Err(CoreError::Storage("create_timeline failed".to_owned()));
            }
            Ok(Self::healthy_timeline())
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            if self.mode == FlakyMode::AppendErr {
                return Err(CoreError::Storage("append failed".to_owned()));
            }
            let events = drafts
                .iter()
                .map(|d| {
                    self.counter += 1;
                    Event {
                        id: EventId::new(),
                        entity: d.entity,
                        event_type: d.event_type.clone(),
                        payload: d.payload.clone(),
                        wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                        seq: Seq::from_u64(self.counter),
                        causation_id: d.causation_id,
                        correlation_id: d.correlation_id,
                        schema_version: d.schema_version,
                        signature: None,
                        payload_hash: Hash::from_bytes([0u8; 32]),
                    }
                })
                .collect();
            Ok(events)
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if self.mode == FlakyMode::ReadErr {
                return Err(CoreError::Storage("read failed".to_owned()));
            }
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            Ok(Timeline::new(TimelineMeta::root("fork")))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            match self.mode {
                FlakyMode::GetTimelineErr => {
                    Err(CoreError::Storage("get_timeline failed".to_owned()))
                }
                FlakyMode::GetTimelineMissing => Ok(None),
                _ => Ok(Some(Self::healthy_timeline())),
            }
        }
    }

    impl EventStore for TrivialStore {
        fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
            let meta = TimelineMeta::root("test");
            Ok(Timeline::new(meta))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            let events = drafts
                .iter()
                .map(|d| {
                    self.counter += 1;
                    Event {
                        id: EventId::new(),
                        entity: d.entity,
                        event_type: d.event_type.clone(),
                        payload: d.payload.clone(),
                        wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                        seq: Seq::from_u64(self.counter),
                        causation_id: d.causation_id,
                        correlation_id: d.correlation_id,
                        schema_version: d.schema_version,
                        signature: None,
                        payload_hash: Hash::from_bytes([0u8; 32]),
                    }
                })
                .collect();
            Ok(events)
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            let meta = TimelineMeta::root("fork");
            Ok(Timeline::new(meta))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            Ok(None)
        }
    }

    #[test]
    fn append_or_duplicate_defaults_fail_closed() {
        let mut store = TrivialStore::new();
        let identity = AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([1; 32]),
            AppendDedupScope::from_keyed_hash([2; 32]),
        );
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.append"),
            CanonicalBytes::from_vec(Vec::new()),
        );
        let append_error = store
            .append_or_duplicate(
                TimelineId::new(),
                identity,
                WallTime::from_micros(3),
                draft.clone(),
            )
            .unwrap_err();
        assert!(append_error.to_string().contains("append-or-duplicate"));
        let cleanup_error = store
            .purge_expired_append_identities(WallTime::from_micros(3))
            .unwrap_err();
        assert!(cleanup_error.to_string().contains("cleanup"));
        let intent_error = store
            .append_intent_or_duplicate(TimelineId::new(), identity, AppendIntent::new(&draft))
            .unwrap_err();
        assert!(intent_error.to_string().contains("store-owned"));
        let bounded_intent_error = store
            .append_intent_or_duplicate_bounded(
                TimelineId::new(),
                identity,
                AppendIntent::new(&draft),
                1,
            )
            .unwrap_err();
        assert!(bounded_intent_error.to_string().contains("store-owned"));
        assert!(store
            .read_event_by_id(TimelineId::new(), EventId::new())
            .unwrap()
            .is_none());
        let bounded_error = store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .unwrap_err();
        assert!(bounded_error.to_string().contains("bounded"));
        let withdrawal_error = store
            .remove_append_identities(AppendDedupScope::from_keyed_hash([2; 32]))
            .unwrap_err();
        assert!(withdrawal_error.to_string().contains("withdrawal"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_requires_preserving_backend() {
        // Default trait stubs reject identity-preserving import (Wave 6 / #87).
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let meta = TimelineMeta::root("original");
        let timeline = Timeline::new(meta);
        let export = TimelineExport {
            timeline,
            events: vec![dummy_event],
            parent_fork_hash: None,
        };

        let mut store = TrivialStore::new();
        let err = import_timeline_with_id(&mut store, export).unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::Storage(ref msg)
                    if msg.contains("import_committed")
                        || msg.contains("create_timeline_with_meta")
            ),
            "expected Wave 6 import rejected by stub defaults, got {err:?}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_accepts_missing_name() {
        let mut meta = TimelineMeta::root("named");
        meta.name = None;
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: None,
        };
        let mut store = TrivialStore::new();
        assert!(import_timeline(&mut store, export).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_store_defaults_fail_closed() {
        let mut store = TrivialStore::new();
        let id = TimelineId::new();
        assert!(store.read_own(id, SeqRange::all()).is_ok());
        let err = store
            .create_timeline_with_meta(TimelineMeta::root("x"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        let err = store.append_committed(id, &[]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        let err = store.delete_timeline(id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        let err = store.chain_hash_at(id, Seq::ZERO).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        let err = store
            .import_committed(TimelineMeta::root("y"), &[])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_with_rollback_surfaces_create_meta_err() {
        // Hit the `?` error path on create_timeline_with_meta inside the helper.
        let mut store = TrivialStore::new();
        let err =
            import_committed_with_rollback(&mut store, TimelineMeta::root("x"), &[]).unwrap_err();
        assert!(
            matches!(err, CoreError::Storage(ref m) if m.contains("create_timeline_with_meta")),
            "got {err:?}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_stub_rejects() {
        let mut store = TrivialStore::new();
        let err = store
            .create_timeline_with_meta(TimelineMeta::root("x"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_stub_rejects() {
        let mut store = TrivialStore::new();
        let err = store.append_committed(TimelineId::new(), &[]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_events_uses_append() {
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("with-events")),
            events: vec![dummy_event],
            parent_fork_hash: None,
        };
        let mut store = TrivialStore::new();
        let imported = import_timeline(&mut store, export).unwrap();
        let _ = imported.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_append_committed_err() {
        struct AppendFailStore {
            created: Option<TimelineId>,
            deleted: bool,
        }
        impl EventStore for AppendFailStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }

            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                let tl = Timeline::new(meta);
                self.created = Some(tl.id());
                Ok(tl)
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("append_committed failed".to_owned()))
            }
            fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
                assert_eq!(Some(id), self.created);
                self.deleted = true;
                Ok(())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let entity = EntityId::new();
        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(b"x".to_vec()),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![event],
            parent_fork_hash: None,
        };
        let mut store = AppendFailStore {
            created: None,
            deleted: false,
        };
        let err = import_timeline_with_id(&mut store, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(
            store.deleted,
            "failed append must roll back via delete_timeline"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_surfaces_rollback_delete_failure() {
        struct AppendAndDeleteFailStore {
            created: Option<TimelineId>,
        }
        impl EventStore for AppendAndDeleteFailStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                let tl = Timeline::new(meta);
                self.created = Some(tl.id());
                Ok(tl)
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("append_committed failed".to_owned()))
            }
            fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
                assert_eq!(Some(id), self.created);
                Err(CoreError::Storage("delete failed".to_owned()))
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new("t"),
                payload: CanonicalBytes::from_vec(b"x".to_vec()),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                payload_hash: Hash::from_bytes([0u8; 32]),
            }],
            parent_fork_hash: None,
        };
        let err = import_timeline_with_id(&mut AppendAndDeleteFailStore { created: None }, export)
            .unwrap_err();
        match err {
            CoreError::Storage(msg) => {
                assert!(msg.contains("import failed"));
                assert!(msg.contains("rollback delete also failed"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_success() {
        struct HappyStore {
            timeline: Option<Timeline>,
        }
        impl EventStore for HappyStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }

            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(self.timeline.clone().filter(|t| t.id() == id))
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                let tl = Timeline::new(meta);
                self.timeline = Some(tl.clone());
                Ok(tl)
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                if let Some(tl) = &mut self.timeline {
                    tl.head = Seq::from_u64(1);
                }
                Ok(())
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                self.timeline = None;
                Ok(())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let timeline = Timeline::new(TimelineMeta::root("keep-id"));
        let expected = timeline.id();
        let export = TimelineExport {
            timeline,
            events: vec![],
            parent_fork_hash: None,
        };
        let imported = import_timeline_with_id(&mut HappyStore { timeline: None }, export).unwrap();
        assert_eq!(imported.id(), expected);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rejects_wrong_returned_id() {
        struct LieStore;
        impl EventStore for LieStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }

            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                _meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Ok(Timeline::new(TimelineMeta::root("lied")))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Ok(())
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Ok(())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("wanted")),
            events: vec![],
            parent_fork_hash: None,
        };
        let err = import_timeline_with_id(&mut LieStore, export).unwrap_err();
        assert!(
            matches!(err, CoreError::Storage(ref msg) if msg.contains("honour")),
            "{err:?}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_fork_requires_preserving_create() {
        // TrivialStore rejects create_timeline_with_meta — fork import needs a real backend.
        let parent = TimelineId::new();
        let meta = TimelineMeta::forked_from(parent, Seq::from_u64(1), "child");
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: None,
        };
        let mut store = TrivialStore::new();
        let err = import_timeline_with_id(&mut store, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)), "{err:?}");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn validate_committed_batch_rejects_gaps_and_dup_ids() {
        struct TestHasher {
            should_match: bool,
        }
        impl Hasher for TestHasher {
            fn genesis_hash(&self) -> Hash {
                Hash::zero()
            }
            fn hash_payload(&self, _payload: &CanonicalBytes) -> Hash {
                if self.should_match {
                    Hash::zero()
                } else {
                    Hash::from_bytes([1u8; 32])
                }
            }
            fn hash_event(
                &self,
                previous_hash: &Hash,
                _event_id_bytes: &[u8],
                _payload: &CanonicalBytes,
            ) -> Hash {
                *previous_hash
            }
        }
        let match_hasher = TestHasher { should_match: true };
        let mismatch_hasher = TestHasher {
            should_match: false,
        };

        let entity = crate::ids::EntityId::new();
        let mk = |seq: u64, id: crate::ids::EventId| Event {
            id,
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(b"x".to_vec()),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::zero(),
        };
        let id = crate::ids::EventId::new();
        let err = validate_committed_batch(Seq::ZERO, &[mk(2, id)], &mut |_| false, &match_hasher)
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        let err = validate_committed_batch(
            Seq::ZERO,
            &[mk(1, id), mk(2, id)],
            &mut |_| false,
            &match_hasher,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));

        let err = validate_committed_batch(
            Seq::ZERO,
            &[mk(1, crate::ids::EventId::new())],
            &mut |_| true,
            &match_hasher,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));

        let err = validate_committed_batch(
            Seq::ZERO,
            &[mk(1, crate::ids::EventId::new())],
            &mut |_| false,
            &mismatch_hasher,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("payload_hash")));

        let err = validate_committed_batch(
            Seq::ZERO,
            &[mk(0, crate::ids::EventId::new())],
            &mut |_| false,
            &match_hasher,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains(">= 1")));

        let ok = validate_committed_batch(Seq::ZERO, &[], &mut |_| false, &match_hasher).unwrap();
        assert!(ok.is_empty());

        // Success path with contiguous events (covers Ok(ordered)).
        let e1 = mk(1, crate::ids::EventId::new());
        let e2 = mk(2, crate::ids::EventId::new());
        let accepted = validate_committed_batch(
            Seq::ZERO,
            &[e2.clone(), e1.clone()], // out of order — must sort
            &mut |_| false,
            &match_hasher,
        )
        .unwrap();
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].id, e1.id);
        assert_eq!(accepted[1].id, e2.id);
    }

    // Counted under llvm-cov: exercises `chain_hash_at` Err through the `?` on raw export.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_raw_chain_hash_err_arm_counted() {
        struct HashFail {
            id: TimelineId,
        }
        impl EventStore for HashFail {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta =
                    TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Err(CoreError::Storage("hash boom".to_owned()))
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let err = export_timeline_raw(&HashFail { id }, id).unwrap_err();
        assert!(
            err.to_string().contains("hash boom"),
            "expected hash boom error, got {err:?}"
        );
    }

    // Prefer export_timeline_own in new code; own/cow wrap raw (legacy name).
    #[test]
    fn export_timeline_own_matches_raw_alias() {
        struct RootStore {
            id: TimelineId,
        }
        impl EventStore for RootStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta = TimelineMeta::root("root");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let store = RootStore { id };
        let own = export_timeline_own(&store, id).unwrap();
        let cow = export_timeline_cow(&store, id).unwrap();
        let raw = export_timeline_raw(&store, id).unwrap();
        assert_eq!(own.timeline.id(), raw.timeline.id());
        assert_eq!(cow.timeline.id(), raw.timeline.id());
        assert!(own.parent_fork_hash.is_none());
    }

    // Counted under llvm-cov: root raw export takes the None fork_point arm.
    #[test]
    fn export_timeline_raw_root_clears_parent_fork_hash_arm() {
        struct RootStore {
            id: TimelineId,
        }
        impl EventStore for RootStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta = TimelineMeta::root("root");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let raw = export_timeline_raw(&RootStore { id }, id).unwrap();
        assert!(raw.timeline.meta.fork_point.is_none());
        assert!(raw.parent_fork_hash.is_none());
    }

    // Counted under llvm-cov: matching parent_fork_hash takes the equality arm.
    #[test]
    fn import_timeline_with_id_accepts_matching_parent_fork_hash() {
        struct MatchStore {
            created: Option<Timeline>,
        }
        impl EventStore for MatchStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(self.created.clone().filter(|t| t.id() == id))
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                let tl = Timeline::new(meta);
                self.created = Some(tl.clone());
                Ok(tl)
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Ok(())
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Ok(())
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::zero()),
        };
        let imported = import_timeline_with_id(&mut MatchStore { created: None }, export).unwrap();
        assert!(imported.meta.fork_point.is_some());
    }

    // Counted under llvm-cov: `chain_hash_at` Err through import_timeline_with_id's `?`.
    #[test]
    fn import_timeline_with_id_chain_hash_err_arm_counted() {
        struct HashFailStore;
        impl EventStore for HashFailStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Err(CoreError::Storage("import hash boom".to_owned()))
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::zero()),
        };
        let err = import_timeline_with_id(&mut HashFailStore, export).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(ref m) if m.contains("import hash boom")
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_flattens_empty_fork_meta() {
        struct ForkStore {
            id: TimelineId,
        }
        impl EventStore for ForkStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                let mut meta = meta;
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let export = export_timeline(&ForkStore { id }, id).unwrap();
        assert!(export.timeline.meta.fork_point.is_none());
        assert!(export.events.is_empty());

        let raw = export_timeline_raw(&ForkStore { id }, id).unwrap();
        assert!(raw.timeline.meta.fork_point.is_some());
        assert!(raw.parent_fork_hash.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_raw_propagates_chain_hash_err() {
        struct HashFailStore {
            id: TimelineId,
        }
        impl EventStore for HashFailStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta =
                    TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Err(CoreError::Storage("hash failed".to_owned()))
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let err = export_timeline_raw(&HashFailStore { id }, id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("hash failed")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_raw_propagates_read_own_err() {
        struct ReadOwnFail {
            id: TimelineId,
        }
        impl EventStore for ReadOwnFail {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn read_own(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("read_own failed".to_owned()))
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                Ok(Some(Timeline::new(TimelineMeta::root("r"))))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let err = export_timeline_raw(&ReadOwnFail { id }, id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("read_own")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_requires_parent_fork_hash() {
        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: None,
        };
        let err = import_timeline_with_id(&mut TrivialStore::new(), export).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(ref m) if m.contains("parent_fork_hash")
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rejects_parent_fork_hash_mismatch() {
        struct HashOkStore;
        impl EventStore for HashOkStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
        meta.id = TimelineId::new();
        // Any non-zero expected hash mismatches HashOkStore's zero chain hash.
        let mut expected = [0u8; 32];
        expected[0] = 1;
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::from_bytes(expected)),
        };
        let err = import_timeline_with_id(&mut HashOkStore, export).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(ref m) if m.contains("chain hash mismatch")
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_sets_head_from_stitched_events() {
        struct ForkWithEvents {
            id: TimelineId,
            event: Event,
        }
        impl EventStore for ForkWithEvents {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(vec![self.event.clone()])
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta =
                    TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                meta.id = self.id;
                let mut tl = Timeline::new(meta);
                tl.head = Seq::from_u64(1); // child-local head; logical export overrides
                Ok(Some(tl))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let entity = crate::ids::EntityId::new();
        let event = Event {
            id: crate::ids::EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(b"x".to_vec()),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(3),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(crate::Signature::from_bytes([1u8; 64])),
            payload_hash: Hash::zero(),
        };
        let original_id = event.id;
        let export = export_timeline(&ForkWithEvents { id, event }, id).unwrap();
        assert!(export.timeline.meta.fork_point.is_none());
        assert_eq!(export.events.len(), 1);
        assert_eq!(export.timeline.head, Seq::from_u64(3));
        // Fork flatten remints EventIds so parent history cannot collide on import.
        assert_ne!(export.events[0].id, original_id);
        assert!(export.events[0].signature.is_none());
    }

    // Intentionally NOT coverage(off): keeps materialize_fork_export_as_root arms counted
    // under llvm-cov when other flatten tests are coverage(off).
    #[test]
    fn export_timeline_flatten_causation_arms_counted() {
        struct S {
            id: TimelineId,
            events: Vec<Event>,
        }
        impl EventStore for S {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(self.events.clone())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta =
                    TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Ok(Hash::zero())
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let entity = EntityId::new();
        let a = EventId::new();
        let b = EventId::new();
        let outside = EventId::new();
        let mk = |eid: EventId, seq: u64, causation: Option<EventId>| Event {
            id: eid,
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(b"x".to_vec()),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(seq),
            causation_id: causation,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(crate::Signature::from_bytes([9u8; 64])),
            payload_hash: Hash::zero(),
        };
        let export = export_timeline(
            &S {
                id,
                events: vec![
                    mk(a, 1, None),
                    mk(b, 2, Some(a)),
                    mk(EventId::new(), 3, Some(outside)),
                ],
            },
            id,
        )
        .unwrap();
        assert_eq!(export.events[1].causation_id, Some(export.events[0].id));
        assert!(export.events[2].causation_id.is_none());
        assert!(export.events.iter().all(|e| e.signature.is_none()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_remaps_causation_within_fork_flatten() {
        struct ForkWithCausation {
            id: TimelineId,
            events: Vec<Event>,
        }
        impl EventStore for ForkWithCausation {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(self.events.clone())
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                if id != self.id {
                    return Ok(None);
                }
                let mut meta =
                    TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "child");
                meta.id = self.id;
                Ok(Some(Timeline::new(meta)))
            }
            fn create_timeline_with_meta(
                &mut self,
                _: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let id = TimelineId::new();
        let entity = EntityId::new();
        let first_id = EventId::new();
        let second_id = EventId::new();
        let outside = EventId::new();
        let mk = |eid: EventId, seq: u64, causation: Option<EventId>| Event {
            id: eid,
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(b"x".to_vec()),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(seq),
            causation_id: causation,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::zero(),
        };
        let export = export_timeline(
            &ForkWithCausation {
                id,
                events: vec![
                    mk(first_id, 1, None),
                    mk(second_id, 2, Some(first_id)),
                    mk(EventId::new(), 3, Some(outside)),
                ],
            },
            id,
        )
        .unwrap();
        assert_ne!(export.events[0].id, first_id);
        assert_eq!(export.events[1].causation_id, Some(export.events[0].id));
        assert!(export.events[2].causation_id.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_get_timeline_err() {
        struct GetFailStore;
        impl EventStore for GetFailStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }

            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Err(CoreError::Storage("get failed".to_owned()))
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Ok(Timeline::new(meta))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Ok(())
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Ok(())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![],
            parent_fork_hash: None,
        };
        let err = import_timeline_with_id(&mut GetFailStore, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_missing_after_create() {
        struct VanishStore;
        impl EventStore for VanishStore {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
                Ok(Vec::new())
            }

            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("unused".to_owned()))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(Vec::new())
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                Ok(Timeline::new(meta))
            }
            fn append_committed(&mut self, _: TimelineId, _: &[Event]) -> Result<(), CoreError> {
                Ok(())
            }
            fn delete_timeline(&mut self, _: TimelineId) -> Result<(), CoreError> {
                Ok(())
            }

            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                import_committed_with_rollback(self, meta, events)
            }
        }

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![],
            parent_fork_hash: None,
        };
        let err = import_timeline_with_id(&mut VanishStore, export).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_stub_rejects() {
        let mut store = TrivialStore::new();
        let err = store.delete_timeline(TimelineId::new()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_read_returns_empty() {
        let store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        let result = store.read(id, SeqRange::all()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_capability_defaults_fail_closed() {
        let store = TrivialStore::new();
        let bounds = EventReadBounds::new(1, 2, 3, 4);
        assert_eq!(bounds.max_payload_bytes(), 1);
        assert_eq!(bounds.max_event_type_bytes(), 2);
        assert_eq!(bounds.max_fork_depth(), 3);
        assert_eq!(bounds.max_events(), 4);
        let read_error = store
            .read_bounded(TimelineId::new(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(read_error.to_string().contains("bounded event reads"));
        let count_error = store.root_timeline_count_bounded(1).unwrap_err();
        assert!(count_error.to_string().contains("bounded root Timeline"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_fork_returns_timeline() {
        let mut store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        let tl = store.fork(id, Seq::ZERO, "fork").unwrap();
        let _ = tl.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_list_timelines_returns_empty() {
        let store = TrivialStore::new();
        assert!(store.list_timelines().unwrap().is_empty());
    }

    #[test]
    fn append_intent_round_trip_excludes_generated_metadata() {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("intent"),
            CanonicalBytes::from_vec(vec![1, 2]),
        );
        let intent = AppendIntent::new(&draft);
        assert_eq!(intent.into_draft().wall_time, None);
        assert!(checked_append_identity_expires_at(WallTime::from_micros(u64::MAX)).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_get_timeline_returns_none() {
        let store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        assert!(store.get_timeline(id).unwrap().is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_all_starts_at_zero() {
        let r = SeqRange::all();
        assert_eq!(r.from, Seq::ZERO);
        assert!(r.to.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_from_seq() {
        let r = SeqRange::from_seq(Seq::from_u64(5));
        assert_eq!(r.from, Seq::from_u64(5));
        assert!(r.to.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_bounded() {
        let r = SeqRange::bounded(Seq::from_u64(3), Seq::from_u64(10));
        assert_eq!(r.from, Seq::from_u64(3));
        assert_eq!(r.to, Some(Seq::from_u64(10)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_get_timeline_err_propagates() {
        let store = FlakyStore::new(FlakyMode::GetTimelineErr);
        let id = TimelineId::new();
        let err = export_timeline(&store, id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_missing_timeline_returns_not_found() {
        let store = FlakyStore::new(FlakyMode::GetTimelineMissing);
        let id = TimelineId::new();
        let err = export_timeline(&store, id).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_read_err_propagates() {
        let store = FlakyStore::new(FlakyMode::ReadErr);
        let id = TimelineId::new();
        let err = export_timeline(&store, id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_create_timeline_err_propagates() {
        let mut store = FlakyStore::new(FlakyMode::CreateTimelineErr);
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![],
            parent_fork_hash: None,
        };
        let err = import_timeline(&mut store, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_append_err_propagates() {
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![dummy_event],
            parent_fork_hash: None,
        };
        let mut store = FlakyStore::new(FlakyMode::AppendErr);
        let err = import_timeline(&mut store, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flaky_store_healthy_export_succeeds() {
        let store = FlakyStore::new(FlakyMode::Healthy);
        let id = TimelineId::new();
        let export = export_timeline(&store, id).unwrap();
        assert!(export.events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flaky_store_healthy_import_with_events_succeeds() {
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"data".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![dummy_event],
            parent_fork_hash: None,
        };
        let mut store = FlakyStore::new(FlakyMode::Healthy);
        let imported = import_timeline(&mut store, export).unwrap();
        let _ = imported.id();
    }
}
