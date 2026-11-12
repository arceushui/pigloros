#![cfg(all(target_os = "linux", feature = "sqlite"))]
#![forbid(unsafe_code)]

use rusqlite::{limits::Limit, Connection, OpenFlags};
use std::os::unix::fs::MetadataExt;

#[test]
fn runtime_facts_on_disposable_database() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("facts.sqlite");
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags_and_vfs(&path, flags, "unix")?;
    let version: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let source: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    println!("runtime_version={version}\nruntime_source_id={source}\nrequested_vfs=unix (successful open)");
    let options = connection
        .prepare("PRAGMA compile_options")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for option in &options {
        println!("compile_option={option}");
    }
    let previous = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    let returned = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65_536)?;
    let bounded = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    let filestat = connection.query_row("SELECT sqlite_filestat('main')", [], |row| {
        row.get::<_, Option<String>>(0)
    });
    println!("filestat_result={filestat:?}");
    let restore_returned = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, previous)?;
    let restored = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    println!("length_limit_initial={previous} set_return={returned} bounded={bounded} restore_return={restore_returned} restored={restored}");
    let journal: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    connection.execute_batch("CREATE TABLE fact (value INTEGER); INSERT INTO fact VALUES (1);")?;
    println!("disposable_journal_mode={journal}");
    for suffix in ["", "-wal", "-shm"] {
        let entry = root.path().join(format!("facts.sqlite{suffix}"));
        match std::fs::symlink_metadata(&entry) {
            Ok(m) => println!(
                "namespace_entry={suffix:?} dev={} ino={} mode={:o} nlink={} size={}",
                m.dev(),
                m.ino(),
                m.mode(),
                m.nlink(),
                m.len()
            ),
            Err(error) => println!("namespace_entry={suffix:?} error={error}"),
        }
    }
    connection.close().map_err(|(_, error)| error)?;
    println!("explicit_close=ok");
    Ok(())
}
