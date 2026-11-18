//! ADR-123 revision 6 §5 native build check (decision G1, Redmine #1451).
//!
//! The workspace builds its bundled `SQLite` with `SQLITE_ENABLE_FILESTAT` and
//! `SQLITE_ENABLE_WALSTAT` through `.cargo/config.toml`. `PRAGMA compile_options`
//! never lists those two flags, so this test asserts what they produce instead:
//! the registered diagnostic functions, on the qualified source.

use rusqlite::Connection;

/// The source ID of the qualified image: rusqlite 0.41.1, libsqlite3-sys 0.39.1,
/// `SQLite` 3.54.1. Every dependency bump, security bumps included, re-qualifies
/// the image and updates this value with the record on Redmine #1451.
const QUALIFIED_SOURCE_ID: &str =
    "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76";

#[test]
fn the_bundled_sqlite_is_the_qualified_source() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    let source: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    assert_eq!(source, QUALIFIED_SOURCE_ID);
    Ok(())
}

#[test]
fn the_bundled_sqlite_registers_both_diagnostic_functions() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    let mut statement = connection.prepare(
        "SELECT DISTINCT name FROM pragma_function_list \
         WHERE name IN ('sqlite_filestat', 'sqlite_walstat') ORDER BY name",
    )?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(names, ["sqlite_filestat", "sqlite_walstat"]);
    Ok(())
}
