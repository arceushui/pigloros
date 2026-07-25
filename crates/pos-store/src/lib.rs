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

// Re-export the port and Wave 6 export/import helpers so hosts need one crate.
pub use pos_core::store::{
    export_timeline, export_timeline_cow, export_timeline_own, export_timeline_raw,
    import_committed_with_rollback, import_timeline, import_timeline_with_id, EventStore, SeqRange,
    TimelineExport,
};
pub use pos_core::CoreError;

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
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        store::SeqRange,
    };

    /// Helper: run a minimal contract against any backend via the port.
    fn contract(store: &mut dyn EventStore) {
        let tl = store.create_timeline("contract-test").unwrap();
        assert_eq!(store.list_timelines().unwrap().len(), 1);
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_memory() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        contract(&mut *store);
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
}
