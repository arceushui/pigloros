#![cfg(all(target_os = "linux", feature = "sqlite"))]
#![forbid(unsafe_code)]

use rusqlite::{limits::Limit, Connection, OpenFlags};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[test]
fn runtime_facts_on_disposable_database() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = root.path().join("facts.sqlite");
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?,
    );
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW;
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
    let journal: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    connection.execute_batch(
        "CREATE TABLE fact (value INTEGER); INSERT INTO fact VALUES (1); BEGIN IMMEDIATE;",
    )?;
    println!("disposable_journal_mode={journal}");
    let previous = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    let returned = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65_536)?;
    let bounded = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    let filestat = connection.query_row("SELECT sqlite_filestat('main')", [], |row| {
        row.get::<_, String>(0)
    });
    let restore_returned = connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, previous)?;
    let restored = connection.limit(Limit::SQLITE_LIMIT_LENGTH)?;
    println!("length_limit_initial={previous} set_return={returned} bounded={bounded} restore_return={restore_returned} restored={restored}");
    let detail = filestat?;
    println!("filestat_json={detail}");
    let json: serde_json::Value = serde_json::from_str(&detail)?;
    for (suffix, pointer) in [("", "/db/h"), ("-wal", "/journal/h"), ("-shm", "/db/shm/h")] {
        let name = root.path().join(format!("facts.sqlite{suffix}"));
        let named = std::fs::symlink_metadata(&name)?;
        let native = json
            .pointer(pointer)
            .and_then(serde_json::Value::as_i64)
            .ok_or("filestat descriptor missing")?;
        let observed = std::fs::metadata(format!("/proc/self/fd/{native}"))?;
        println!("descriptor_fact={suffix:?} fd={native} name_dev={} name_ino={} name_mode={:o} name_nlink={} proc_dev={} proc_ino={} match={}",named.dev(),named.ino(),named.mode(),named.nlink(),observed.dev(),observed.ino(), named.dev()==observed.dev() && named.ino()==observed.ino());
    }
    connection.execute_batch("ROLLBACK")?;
    connection.close().map_err(|(_, error)| error)?;
    println!("explicit_close=ok");
    Ok(())
}
