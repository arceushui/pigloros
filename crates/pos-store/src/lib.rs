#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-store` — `EventStore` port adapters and backend factory.
//!
//! # Domain-Driven Design
//!
//! The domain port ([`EventStore`]) is defined in `pos-core`. This crate
//! provides the infrastructure adapters (in-memory, `SQLite`) and a factory
//! ([`open_store`]) so callers hold `Box<dyn EventStore>` and never import
//! a concrete backend type.
//!
//! # Consumer import path
//!
//! Prefer importing export/import helpers from **this crate** together with
//! [`open_store`]:
//!
//! | Intent | Export | Import |
//! |--------|--------|--------|
//! | Independent clone | [`export_timeline`] | [`import_timeline`] |
//! | Identity `CoW` | [`export_timeline_own`] | [`import_timeline_with_id`] |
//! | Verified identity | [`export_timeline_own`] | [`import_timeline_with_verified_signatures`] |
//!
//! Signatures cover **payload bytes only** (not metadata). See
//! [`import_timeline_with_verified_signatures`].
//!
//! # Backend features
//!
//! | Feature | Default | Dependency |
//! |---------|---------|------------|
//! | `sqlite` | ✅ on | `rusqlite` (WAL; encryption / `SQLCipher` deferred) |
//!
//! Disable `SQLite` entirely: `--no-default-features`
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod memory;
pub mod stitch;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-export the port, its append-deduplication surface, and Wave 6 export/import helpers so
// hosts need one crate.
pub use pos_core::store::{
    append_identity_expires_at, export_timeline, export_timeline_cow, export_timeline_own,
    export_timeline_raw, import_committed_with_rollback, import_timeline, import_timeline_with_id,
    AppendDedupKey, AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome,
    EventStore, PurgeOutcome, SeqRange, TimelineExport, APPEND_IDENTITY_RETENTION_MICROS,
};
pub use pos_core::{
    CanonicalBytes, CoreError, CorrelationId, EntityId, Event, EventDraft, EventId, Kind,
    TimelineId, WallTime,
};

/// Selects which backend [`open_store`] constructs.
///
/// `Memory` is always available. The `Sqlite` variants require the
/// `sqlite` Cargo feature (enabled by default).
#[derive(Clone, Debug)]
pub enum StoreConfig {
    /// Pure in-memory store. Fast, no persistence. Ideal for tests and
    /// short-lived experiments.
    Memory,

    /// `SQLite` WAL store at a filesystem path.
    ///
    /// Requires the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    Sqlite {
        /// Filesystem path to the `.db` file. Created if it does not exist.
        path: String,
    },

    /// `SQLite` store backed by a private in-memory database.
    ///
    /// Behaves identically to [`StoreConfig::Sqlite`] but without touching
    /// the filesystem. Useful for tests that need full `SQLite` semantics.
    ///
    /// Requires the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    SqliteInMemory,
}

/// Construct an event store backend and return it as `Box<dyn EventStore>`.
///
/// This is the single entry point for infrastructure wiring. Callers
/// should never import `MemoryStore` or `SqliteStore` directly.
///
/// # Errors
///
/// Returns [`CoreError::Storage`] if the backend cannot be initialised
/// (e.g. the `SQLite` file path is not writable or schema migration fails).
///
/// # Panics
///
/// Panics if in-memory `SQLite` store cannot be opened (should never happen in practice).
///
/// # Examples
///
/// ```rust
/// use pos_core::{
///     clock::Seq,
///     event::{CanonicalBytes, EventDraft, Kind},
///     ids::EntityId,
///     store::SeqRange,
/// };
/// use pos_store::{
///     export_timeline_own, import_timeline_with_id, open_store, StoreConfig,
/// };
///
/// // Parent-then-child CoW sync (identity-preserving).
/// let mut src = open_store(StoreConfig::Memory).unwrap();
/// let root = src.create_timeline("root").unwrap();
/// let entity = EntityId::new();
/// src.append(
///     root.id(),
///     &[EventDraft::new(
///         entity,
///         Kind::new("demo"),
///         CanonicalBytes::from_vec(b"p1".to_vec()),
///     )],
/// )
/// .unwrap();
/// let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();
///
/// let mut dst = open_store(StoreConfig::Memory).unwrap();
/// import_timeline_with_id(&mut *dst, export_timeline_own(&*src, root.id()).unwrap()).unwrap();
/// import_timeline_with_id(&mut *dst, export_timeline_own(&*src, child.id()).unwrap()).unwrap();
/// assert_eq!(dst.read(child.id(), SeqRange::all()).unwrap().len(), 1);
/// ```
pub fn open_store(config: StoreConfig) -> Result<Box<dyn EventStore>, CoreError> {
    open_store_with_hasher(config, Box::new(pos_crypto::chain::Blake3Hasher))
}

/// Like [`open_store`] but with a custom [`Hasher`] for hash-chain computation.
///
/// # Errors
/// Returns [`CoreError::Storage`] if the backend cannot be initialised.
pub fn open_store_with_hasher(
    config: StoreConfig,
    hasher: Box<dyn pos_core::Hasher>,
) -> Result<Box<dyn EventStore>, CoreError> {
    match config {
        StoreConfig::Memory => Ok(Box::new(memory::MemoryStore::with_hasher(hasher))),
        #[cfg(feature = "sqlite")]
        StoreConfig::Sqlite { path } => {
            let store = sqlite::SqliteStore::open_with_hasher(&path, hasher)?;
            Ok(Box::new(store))
        }
        #[cfg(feature = "sqlite")]
        StoreConfig::SqliteInMemory => {
            let store = sqlite::SqliteStore::open_in_memory_with_hasher(hasher)?;
            Ok(Box::new(store))
        }
    }
}

/// Cryptographically verify signed events in `export`, then identity-import.
///
/// Every event must carry a signature that verifies under `public_key` against its
/// **payload bytes only** (event metadata is not covered). An empty event list is allowed.
///
/// Use this when the export is uniformly signed by one key. For mixed unsigned events
/// or multiple signers, call [`pos_crypto::signing::verify_events`] (or filter) yourself,
/// then [`import_timeline_with_id`].
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] if any event is unsigned or fails
/// verify, or any error from [`import_timeline_with_id`].
pub fn import_timeline_with_verified_signatures(
    store: &mut dyn EventStore,
    export: TimelineExport,
    public_key: &pos_core::PublicKey,
) -> Result<pos_core::Timeline, CoreError> {
    let vk = pos_crypto::signing::verifying_key_from_public_key(public_key)?;
    pos_crypto::signing::verify_events_all_signed(&vk, &export.events)?;
    import_timeline_with_id(store, export)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run a minimal contract against any backend via the port.
    fn contract(store: &mut dyn EventStore) {
        let tl = store.create_timeline("contract-test").unwrap();
        assert_eq!(store.list_timelines().unwrap().len(), 1);
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert!(events.is_empty());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_scope_withdrawal(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
    ) {
        let first = store
            .append_or_duplicate(
                timeline,
                append_identity(3, 4),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .unwrap();
        let _ = appended_event_id(first);
        assert_eq!(
            store
                .remove_append_identities(AppendDedupScope::from_keyed_hash([4; 32]))
                .unwrap(),
            1
        );
        let after_withdrawal = store
            .append_or_duplicate(
                timeline,
                append_identity(3, 4),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .unwrap();
        let _ = appended_event_id(after_withdrawal);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn appended_event_id(outcome: AppendOrDuplicateOutcome) -> EventId {
        match outcome {
            AppendOrDuplicateOutcome::Appended(event) => event.id,
            AppendOrDuplicateOutcome::Duplicate { .. } | AppendOrDuplicateOutcome::Conflict => {
                panic!("identified append must append an Event")
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_wall_time_contract(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
        event_id: EventId,
    ) {
        let duplicate = store
            .append_or_duplicate(
                timeline,
                append_identity(1, 2),
                WallTime::from_micros(21),
                draft.clone(),
            )
            .unwrap();
        assert_eq!(duplicate, AppendOrDuplicateOutcome::Duplicate { event_id });
        let mut retry_without_wall_time = draft.clone();
        retry_without_wall_time.wall_time = None;
        assert_eq!(
            store
                .append_or_duplicate(
                    timeline,
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    retry_without_wall_time,
                )
                .unwrap(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
        // Generated Event metadata is not part of canonical retry intent. A
        // caller retrying with a different wall-time hint remains a duplicate;
        // identified append owns admission time at the store boundary.
        let mut wall_time_variant = draft.clone();
        wall_time_variant.wall_time = Some(WallTime::from_micros(31));
        assert_eq!(
            store
                .append_or_duplicate(
                    timeline,
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    wall_time_variant,
                )
                .unwrap(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
    }

    fn assert_timeline_deletion_removes_identities(
        store: &mut dyn EventStore,
        timeline: TimelineId,
        draft: &EventDraft,
    ) {
        store.delete_timeline(timeline).unwrap();
        let replacement = store
            .create_timeline("append-or-duplicate-replacement")
            .unwrap();
        let first_retry = store
            .append_or_duplicate(
                replacement.id(),
                append_identity(1, 2),
                WallTime::from_micros(50),
                draft.clone(),
            )
            .unwrap();
        let _ = appended_event_id(first_retry);
        let second_retry = store
            .append_or_duplicate(
                replacement.id(),
                append_identity(3, 4),
                WallTime::from_micros(50),
                draft.clone(),
            )
            .unwrap();
        let _ = appended_event_id(second_retry);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract(store: &mut dyn EventStore) {
        let timeline = store.create_timeline("append-or-duplicate").unwrap();
        let mut draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.append"),
            CanonicalBytes::from_vec(b"retained-canonical-content".to_vec()),
        )
        .with_wall_time(WallTime::from_micros(30));
        draft.causation_id = Some(EventId::new());
        draft.correlation_id = Some(CorrelationId::new());
        let first = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(20),
                draft.clone(),
            )
            .unwrap();
        let event_id = appended_event_id(first);
        let admitted_events = store.read(timeline.id(), SeqRange::all()).unwrap();
        assert_eq!(admitted_events[0].causation_id, draft.causation_id);
        assert_eq!(admitted_events[0].correlation_id, draft.correlation_id);
        assert_wall_time_contract(store, timeline.id(), &draft, event_id);
        let conflict_draft = EventDraft::new(
            draft.entity,
            Kind::new("test.append"),
            CanonicalBytes::from_vec(b"different-retained-canonical-content".to_vec()),
        );
        let conflict = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(21),
                conflict_draft,
            )
            .unwrap();
        assert_eq!(conflict, AppendOrDuplicateOutcome::Conflict);
        assert_eq!(store.read(timeline.id(), SeqRange::all()).unwrap().len(), 1);

        assert_eq!(
            store
                .purge_expired_append_identities(WallTime::from_micros(
                    20 + APPEND_IDENTITY_RETENTION_MICROS - 1,
                ))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .purge_expired_append_identities(WallTime::from_micros(
                    20 + APPEND_IDENTITY_RETENTION_MICROS,
                ))
                .unwrap(),
            1
        );
        match store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .unwrap()
        {
            AppendOrDuplicateOutcome::Appended(_) => {}
            AppendOrDuplicateOutcome::Duplicate { .. } | AppendOrDuplicateOutcome::Conflict => {
                panic!("expired identity must append a new Event")
            }
        }
        assert_eq!(store.read(timeline.id(), SeqRange::all()).unwrap().len(), 2);

        assert_timeline_scoped_and_delayed_expiry(store, timeline.id(), &draft);

        assert_scope_withdrawal(store, timeline.id(), &draft);
        assert_timeline_deletion_removes_identities(store, timeline.id(), &draft);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_timeline_scoped_and_delayed_expiry(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
    ) {
        let other_timeline = store.create_timeline("append-or-duplicate-other").unwrap();
        // A target Timeline is part of the admission boundary: reusing an
        // opaque key against another Timeline must not disclose the retained
        // Event or return its EventId.
        assert_eq!(
            store
                .append_or_duplicate(
                    other_timeline.id(),
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    draft.clone(),
                )
                .unwrap(),
            AppendOrDuplicateOutcome::Conflict
        );
        assert!(matches!(
            store.append_or_duplicate(
                pos_core::TimelineId::new(),
                append_identity(1, 2),
                WallTime::from_micros(21),
                draft.clone(),
            ),
            Err(pos_core::CoreError::TimelineNotFound(_))
        ));

        // Admission must replace a logically expired identity even when
        // asynchronous maintenance has not purged it yet.
        let delayed_identity = append_identity(13, 14);
        let delayed_draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.delayed-expiry"),
            CanonicalBytes::from_vec(b"delayed".to_vec()),
        );
        let delayed_first = store
            .append_or_duplicate(
                timeline,
                delayed_identity,
                WallTime::from_micros(100),
                delayed_draft.clone(),
            )
            .unwrap();
        let _ = appended_event_id(delayed_first);
        assert!(matches!(
            store.append_or_duplicate(
                timeline,
                delayed_identity,
                WallTime::from_micros(100 + APPEND_IDENTITY_RETENTION_MICROS),
                delayed_draft,
            ),
            Ok(AppendOrDuplicateOutcome::Appended(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_memory() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        contract(&mut *store);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract_memory() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        append_or_duplicate_contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_sqlite_in_memory() {
        let mut store = open_store(StoreConfig::SqliteInMemory).unwrap();
        contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract_sqlite() {
        let mut store = open_store(StoreConfig::SqliteInMemory).unwrap();
        append_or_duplicate_contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_sqlite_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        let mut store = open_store(StoreConfig::Sqlite { path }).unwrap();
        contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_store_sqlite_rejects_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = open_store(StoreConfig::Sqlite {
            path: dir.path().to_str().unwrap().to_owned(),
        });
        assert!(matches!(result, Err(CoreError::Storage(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_import_roundtrip_memory() {
        let mut src = open_store(StoreConfig::Memory).unwrap();
        let tl = src.create_timeline("source").unwrap();
        let entity = EntityId::new();
        let drafts = vec![
            EventDraft::new(
                entity,
                Kind::new("test.event"),
                CanonicalBytes::from_vec(b"hello".to_vec()),
            ),
            EventDraft::new(
                entity,
                Kind::new("test.event"),
                CanonicalBytes::from_vec(b"world".to_vec()),
            ),
        ];
        src.append(tl.id(), &drafts).unwrap();

        // Export from source
        let export = pos_core::store::export_timeline(src.as_ref(), tl.id()).unwrap();
        assert_eq!(export.events.len(), 2);

        // Import into a fresh store — different backend, same data
        let mut dst = open_store(StoreConfig::Memory).unwrap();
        let imported = pos_core::store::import_timeline(dst.as_mut(), export).unwrap();
        let events = dst.read(imported.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"hello");
        assert_eq!(events[1].payload.as_slice(), b"world");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_memory_import_sqlite() {
        let mut src = open_store(StoreConfig::Memory).unwrap();
        let tl = src.create_timeline("mem-src").unwrap();
        let entity = EntityId::new();
        src.append(
            tl.id(),
            &[EventDraft::new(
                entity,
                Kind::new("e"),
                CanonicalBytes::from_vec(b"data".to_vec()),
            )],
        )
        .unwrap();

        let export = pos_core::store::export_timeline(src.as_ref(), tl.id()).unwrap();

        let mut dst = open_store(StoreConfig::SqliteInMemory).unwrap();
        let imported = pos_core::store::import_timeline(dst.as_mut(), export).unwrap();
        let events = dst.read(imported.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"data");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_accepts_valid_and_rejects_bad() {
        use pos_core::{
            clock::{Seq, WallTime},
            event::{Event, SchemaVersion},
            ids::EventId,
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
        };
        use pos_crypto::signing::{generate_keypair, public_key_from_verifying_key, sign};

        let (sk, vk) = generate_keypair();
        let pk = public_key_from_verifying_key(&vk);
        let payload = CanonicalBytes::from_vec(b"signed".to_vec());
        let sig = sign(&sk, &payload);
        let entity = EntityId::new();
        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(sig),
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("signed")),
            events: vec![event.clone()],
            parent_fork_hash: None,
        };

        let mut ok_store = open_store(StoreConfig::Memory).unwrap();
        import_timeline_with_verified_signatures(ok_store.as_mut(), export.clone(), &pk).unwrap();

        let (_, reject_vk) = generate_keypair();
        let reject_key = public_key_from_verifying_key(&reject_vk);
        let mut bad_store = open_store(StoreConfig::Memory).unwrap();
        let err = import_timeline_with_verified_signatures(bad_store.as_mut(), export, &reject_key)
            .unwrap_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_rejects_invalid_public_key() {
        use pos_core::{
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
            PublicKey,
        };

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![],
            parent_fork_hash: None,
        };
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff;
        let bad = PublicKey::from_bytes(bytes);
        let err =
            import_timeline_with_verified_signatures(store.as_mut(), export, &bad).unwrap_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_rejects_unsigned_event() {
        use pos_core::{
            clock::{Seq, WallTime},
            event::{Event, SchemaVersion},
            ids::EventId,
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
        };
        use pos_crypto::signing::{generate_keypair, public_key_from_verifying_key};

        let (_, vk) = generate_keypair();
        let pk = public_key_from_verifying_key(&vk);
        let payload = CanonicalBytes::from_vec(b"unsigned".to_vec());
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("u")),
            events: vec![Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new("t"),
                payload: payload.clone(),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            }],
            parent_fork_hash: None,
        };
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let err =
            import_timeline_with_verified_signatures(store.as_mut(), export, &pk).unwrap_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_store_sqlite_in_memory_propagates_open_error() {
        sqlite::FAIL_OPEN_IN_MEMORY.with(|f| f.set(true));
        let result = open_store(StoreConfig::SqliteInMemory);
        sqlite::FAIL_OPEN_IN_MEMORY.with(|f| f.set(false));
        assert!(
            matches!(result, Err(CoreError::Storage(_))),
            "expected Storage error from injected open_in_memory failure"
        );
    }

    #[test]
    fn store_owned_clock_drives_canonical_intent_and_bounded_cleanup() {
        let admission = WallTime::from_micros(APPEND_IDENTITY_RETENTION_MICROS + 42);
        let mut store =
            memory::MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(admission)));
        let timeline = store.create_timeline("clock").unwrap();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("clock.test"),
            CanonicalBytes::from_vec(b"payload".to_vec()),
        );
        let intent = AppendIntent::new(&draft);
        let first = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(9, 9),
                WallTime::from_micros(0),
                draft.clone(),
            )
            .unwrap();
        let event = match first {
            AppendOrDuplicateOutcome::Appended(event) => event,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let replaced = store
            .append_intent_or_duplicate(timeline.id(), append_identity(9, 9), intent.clone())
            .unwrap();
        assert!(matches!(replaced, AppendOrDuplicateOutcome::Appended(_)));
        let second = store
            .append_intent_or_duplicate(timeline.id(), append_identity(8, 8), intent.clone())
            .unwrap();
        let second_event = match second {
            AppendOrDuplicateOutcome::Appended(event) => event,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(second_event.wall_time, admission);
        store
            .append_or_duplicate(
                timeline.id(),
                append_identity(10, 10),
                WallTime::from_micros(0),
                draft,
            )
            .unwrap();
        assert_eq!(
            store
                .append_intent_or_duplicate(timeline.id(), append_identity(8, 8), intent)
                .unwrap(),
            AppendOrDuplicateOutcome::Duplicate {
                event_id: second_event.id
            }
        );
        let outcome = store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(
            outcome,
            PurgeOutcome {
                removed: 1,
                more_may_remain: false
            }
        );
        assert_ne!(event.id, second_event.id);
    }
}
