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
//! # Backend features
//!
//! | Feature | Default | Dependency |
//! |---------|---------|------------|
//! | `sqlite` | ✅ on | `rusqlite` (WAL; encryption / `SQLCipher` deferred) |
//!
//! Disable `SQLite` entirely: `--no-default-features`
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod memory;
pub mod stitch;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-export the port so callers only need one import.
pub use pos_core::store::{EventStore, SeqRange, TimelineExport};
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
/// # Examples
///
/// ```rust
/// use pos_store::{open_store, StoreConfig};
///
/// let mut store = open_store(StoreConfig::Memory).unwrap();
/// let tl = store.create_timeline("my-world").unwrap();
/// ```
pub fn open_store(config: StoreConfig) -> Result<Box<dyn EventStore>, CoreError> {
    match config {
        StoreConfig::Memory => Ok(Box::new(memory::MemoryStore::new())),
        #[cfg(feature = "sqlite")]
        StoreConfig::Sqlite { path } => {
            let store = sqlite::SqliteStore::open(&path)?;
            Ok(Box::new(store))
        }
        #[cfg(feature = "sqlite")]
        StoreConfig::SqliteInMemory => {
            let store = sqlite::SqliteStore::open_in_memory()?;
            Ok(Box::new(store))
        }
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
        let export = src.export_timeline(tl.id()).unwrap();
        assert_eq!(export.events.len(), 2);

        // Import into a fresh store — different backend, same data
        let mut dst = open_store(StoreConfig::Memory).unwrap();
        let imported = dst.import_timeline(export).unwrap();
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

        let export = src.export_timeline(tl.id()).unwrap();

        let mut dst = open_store(StoreConfig::SqliteInMemory).unwrap();
        let imported = dst.import_timeline(export).unwrap();
        let events = dst.read(imported.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"data");
    }
}
