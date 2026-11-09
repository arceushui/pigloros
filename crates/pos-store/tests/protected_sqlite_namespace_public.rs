#![cfg(all(target_os = "linux", feature = "sqlite"))]
//! Ordinary factory refusals, not qualified native/owner activation evidence.

use pos_core::CoreError;
use pos_store::protected_sqlite_namespace::{
    refuse_reserved_database_path, refuse_reserved_filename, refuse_reserved_path,
};
use pos_store::sqlite::SqliteStore;
use pos_store::trusted_clock::SqliteTrustedClockAuthorityV1;
use pos_store::{
    open_owntracks_enrollment_store, open_store, open_store_read_only, open_store_with_hasher,
    StoreConfig,
};
use std::path::{Path, PathBuf};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
const MARKER: &str = ".pigloros-store-namespace-v1";

fn mark(directory: &Path) -> std::io::Result<()> {
    std::fs::create_dir(directory.join(MARKER))
}
fn closed(result: Result<(), CoreError>) {
    assert_eq!(
        result.err().map(|error| error.to_string()),
        Some("storage error: ordinary SQLite open cannot use the protected namespace".to_owned())
    );
}
fn path_text(path: &Path) -> Fallible<&str> {
    path.to_str()
        .ok_or_else(|| "fixture path is not UTF-8".into())
}

#[test]
fn every_ordinary_store_factory_refuses_before_creating_main_or_companions() -> TestResult {
    let directory = tempfile::tempdir()?;
    mark(directory.path())?;
    let database = directory.path().join("main.db");
    let path = path_text(&database)?;
    closed(SqliteStore::open(path).map(drop));
    closed(SqliteStore::open_read_only(path).map(drop));
    closed(
        SqliteStore::open_with_hasher(path, Box::new(pos_crypto::chain::Blake3Hasher)).map(drop),
    );
    closed(SqliteStore::open_with_clock(path, Box::new(pos_core::SystemAdmissionClock)).map(drop));
    closed(open_store(StoreConfig::Sqlite { path: path.into() }).map(drop));
    closed(open_store_read_only(path).map(drop));
    closed(
        open_store_with_hasher(
            StoreConfig::Sqlite { path: path.into() },
            Box::new(pos_crypto::chain::Blake3Hasher),
        )
        .map(drop),
    );
    closed(open_owntracks_enrollment_store(path).map(drop));
    closed(SqliteTrustedClockAuthorityV1::open(path).map(drop));
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
    assert!(!database.exists());
    Ok(())
}

#[test]
fn existing_database_and_each_native_companion_cannot_be_reopened_as_another_database() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("main.db");
    drop(SqliteStore::open(path_text(&database)?)?);
    mark(directory.path())?;
    let original = std::fs::read(&database)?;
    for name in [
        "main.db",
        "main.db-wal",
        "main.db-shm",
        "main.db-journal",
        "another.db",
    ] {
        let candidate = directory.path().join(name);
        closed(SqliteStore::open(path_text(&candidate)?).map(drop));
        closed(SqliteStore::open_read_only(path_text(&candidate)?).map(drop));
        closed(SqliteTrustedClockAuthorityV1::open(path_text(&candidate)?).map(drop));
    }
    assert_eq!(std::fs::read(&database)?, original);
    assert!(!directory.path().join("another.db").exists());
    Ok(())
}

#[test]
fn reserved_entry_of_any_kind_denies_and_descendants_do_not_escape() -> TestResult {
    let directory = tempfile::tempdir()?;
    let child = directory.path().join("child");
    std::fs::create_dir(&child)?;
    let candidate = child.join("main.db");
    let marker = directory.path().join(MARKER);
    std::fs::write(&marker, b"not an authority record")?;
    closed(refuse_reserved_path(&candidate));
    std::fs::remove_file(&marker)?;
    std::os::unix::fs::symlink(directory.path().join("missing"), &marker)?;
    closed(refuse_reserved_path(&candidate));
    std::fs::remove_file(&marker)?;
    std::fs::create_dir(&marker)?;
    closed(refuse_reserved_path(&candidate));
    closed(refuse_reserved_path(
        &child.join("not-created").join("deep.db"),
    ));
    assert!(!candidate.exists());
    Ok(())
}

#[test]
fn uri_authorities_escapes_fragments_and_native_zero_termination_cannot_hide_namespace(
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let private = directory.path().join("private space");
    std::fs::create_dir(&private)?;
    mark(&private)?;
    let database = private.join("main.db");
    let plain = path_text(&database)?;
    let encoded = plain.replace(' ', "%20").replace('/', "%2f");
    for filename in [
        format!("file:{plain}"),
        format!("file://{plain}?mode=rwc"),
        format!("file://localhost{plain}?mode=ro"),
        format!("file:{encoded}?mode=ro#ignored"),
        format!("file:{plain}%00ignored/outside?mode=rwc"),
        format!("file:{plain}#ignored?mode=memory"),
    ] {
        closed(refuse_reserved_filename(&filename));
        closed(SqliteStore::open(&filename).map(drop));
    }
    closed(refuse_reserved_filename("file://foreign-host/no-database"));
    assert!(!database.exists());
    Ok(())
}

#[test]
fn directory_and_leaf_aliases_including_dangling_links_refuse() -> TestResult {
    let private = tempfile::tempdir()?;
    let aliases = tempfile::tempdir()?;
    let database = private.path().join("main.db");
    std::fs::write(&database, b"native proof is not supplied by this fixture")?;
    mark(private.path())?;
    let directory_alias = aliases.path().join("directory");
    std::os::unix::fs::symlink(private.path(), &directory_alias)?;
    closed(refuse_reserved_path(&directory_alias.join("main.db")));
    let leaf = aliases.path().join("leaf.db");
    std::os::unix::fs::symlink(&database, &leaf)?;
    closed(refuse_reserved_path(&leaf));
    let dangling = aliases.path().join("dangling.db");
    std::os::unix::fs::symlink(private.path().join("not-created.db"), &dangling)?;
    closed(refuse_reserved_path(&dangling));
    let relative = aliases.path().join("relative.db");
    std::os::unix::fs::symlink("leaf.db", &relative)?;
    closed(refuse_reserved_path(&relative));
    Ok(())
}

#[test]
fn native_database_paths_screen_implicit_uri_targets_and_exact_non_utf8_bytes() -> TestResult {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let private = tempfile::tempdir()?;
    mark(private.path())?;
    let uri = format!("file:{}/main.db", path_text(private.path())?);
    // Its literal path is outside the reserved namespace, while SQLite's
    // default URI interpretation names the reserved directory directly.
    refuse_reserved_path(Path::new(&uri))?;
    closed(refuse_reserved_database_path(Path::new(&uri)));
    let mut bytes = b"file:".to_vec();
    bytes.extend_from_slice(private.path().as_os_str().as_bytes());
    bytes.extend_from_slice(b"/non-utf8-\xff.db");
    let non_utf8 = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    refuse_reserved_path(&non_utf8)?;
    closed(refuse_reserved_database_path(&non_utf8));
    let ordinary = tempfile::tempdir()?;
    refuse_reserved_database_path(&ordinary.path().join("main.db"))?;
    assert_eq!(std::fs::read_dir(private.path())?.count(), 1);
    Ok(())
}

#[test]
fn unreserved_plain_relative_uri_and_memory_names_keep_ordinary_semantics() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("ordinary.db");
    refuse_reserved_path(&database)?;
    drop(SqliteStore::open(path_text(&database)?)?);
    drop(SqliteStore::open_read_only(&format!(
        "file:{}?mode=ro#fragment",
        path_text(&database)?
    ))?);
    for filename in [
        "",
        ":memory:",
        "file:",
        "file::memory:?cache=shared",
        "file:?mode=memory",
        "./not-created.db",
        "file:./not-created.db?mode=rwc",
    ] {
        refuse_reserved_filename(filename)?;
    }
    drop(SqliteStore::open(":memory:")?);
    let special = directory.path().join("escapes?#%GZ%aF%A0%ff");
    refuse_reserved_filename(&format!(
        "file:{}",
        path_text(&special)?.replace('?', "%3f").replace('#', "%23")
    ))?;
    assert!(!special.exists());
    Ok(())
}

#[test]
fn uncertain_filesystem_views_and_overlong_missing_alias_chains_refuse_closed() -> TestResult {
    closed(refuse_reserved_path(Path::new("nul\0path")));
    let directory = tempfile::tempdir()?;
    let parent_file = directory.path().join("not-directory");
    std::fs::write(&parent_file, b"x")?;
    closed(refuse_reserved_path(&parent_file.join("main.db")));
    let cycle = directory.path().join("cycle");
    std::os::unix::fs::symlink("cycle", &cycle)?;
    closed(refuse_reserved_path(&cycle));
    let mut deep = PathBuf::from(directory.path());
    for _ in 0..65 {
        deep.push("missing");
    }
    closed(refuse_reserved_path(&deep));
    Ok(())
}

#[test]
fn vanished_current_directory_refuses_without_native_open() -> TestResult {
    const CHILD: &str = "PIGLOROS_NAMESPACE_MISSING_CWD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // Only the isolated child changes its working directory. It creates
        // and removes its own directory, never one supplied through the env.
        let root = tempfile::tempdir()?;
        let working = root.path().join("native-namespace-missing-cwd");
        std::fs::create_dir(&working)?;
        std::env::set_current_dir(&working)?;
        std::fs::remove_dir(&working)?;
        // Native memory names need no filesystem view; literal paths do.
        refuse_reserved_filename("")?;
        refuse_reserved_filename(":memory:")?;
        closed(refuse_reserved_path(Path::new("main.db")));
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
        return Ok(());
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "vanished_current_directory_refuses_without_native_open",
            "--nocapture",
            "--format=pretty",
        ])
        .env(CHILD, "1")
        .output()?;
    assert!(
        output.status.success(),
        "isolated cwd refusal failed: {output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
    Ok(())
}
