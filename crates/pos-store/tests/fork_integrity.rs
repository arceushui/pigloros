#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

use pos_core::{CoreError, EventReadBounds, EventStore, Seq};
use pos_store::sqlite::SqliteStore;
use rusqlite::params;

#[test]
fn sqlite_public_read_rejects_a_fork_without_a_fork_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = SqliteStore::open(path)?;
    let parent = store.create_timeline("fork-parent")?;
    let child = store.fork(parent.id(), Seq::ZERO, "fork-child")?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    let updated = connection.execute(
        "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
        params![child.id().to_string()],
    )?;
    assert_eq!(updated, 1);
    drop(connection);

    let store = SqliteStore::open(path)?;
    let bounds = EventReadBounds::new(1, usize::MAX, 1, 1);
    assert!(matches!(
        store.read_bounded(child.id(), pos_core::SeqRange::all(), bounds),
        Err(CoreError::Storage(message)) if message.contains("missing its Fork sequence")
    ));
    Ok(())
}
