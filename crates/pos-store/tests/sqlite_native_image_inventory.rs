#![cfg(all(target_os = "linux", feature = "sqlite"))]

use std::error::Error;
use std::fs;

use rusqlite::Connection;
use serde_json::json;

#[test]
fn captures_current_sqlite_image() -> Result<(), Box<dyn Error>> {
    let connection = Connection::open_in_memory()?;
    let runtime_version: String =
        connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let runtime_source_id: String =
        connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    let header_version = rusqlite::ffi::SQLITE_VERSION.to_str()?;
    let header_source_id = rusqlite::ffi::SQLITE_SOURCE_ID.to_str()?;
    let compile_options = {
        let mut statement = connection.prepare(
            "SELECT compile_options FROM pragma_compile_options ORDER BY compile_options",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let filestat_functions: i64 = connection.query_row(
        "SELECT count(*) FROM pragma_function_list WHERE name = 'sqlite_filestat'",
        [],
        |row| row.get(0),
    )?;
    let process_maps = fs::read_to_string("/proc/self/maps")?;
    let report = json!({
        "version": 1,
        "purpose": "ordinary SQLite test-process image inventory",
        "connection": "in-memory",
        "checkout": std::env::var("GITHUB_SHA")?,
        "executable": std::env::current_exe()?,
        "runtime_version": runtime_version,
        "runtime_source_id": runtime_source_id,
        "header_version": header_version,
        "header_source_id": header_source_id,
        "header_version_number": rusqlite::ffi::SQLITE_VERSION_NUMBER,
        "runtime_version_number": rusqlite::version_number(),
        "compile_options": compile_options,
        "sqlite_filestat_function_count": filestat_functions,
        "process_maps": process_maps,
    });
    fs::write(
        std::env::var_os("SQLITE_IMAGE_REPORT").ok_or("missing inventory output path")?,
        serde_json::to_vec_pretty(&report)?,
    )?;
    assert_eq!(runtime_version, header_version);
    assert_eq!(runtime_source_id, header_source_id);
    assert_eq!(
        rusqlite::version_number(),
        rusqlite::ffi::SQLITE_VERSION_NUMBER
    );
    Ok(())
}
