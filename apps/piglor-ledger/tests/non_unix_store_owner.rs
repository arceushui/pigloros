#![cfg(not(unix))]

use piglor_ledger::{open_store, Source};

#[test]
fn store_source_fails_closed_without_a_supported_key_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");

    for supplied_key in [None, Some(key.as_path())] {
        let error = open_store(&Source::Store(database.clone()), supplied_key)
            .err()
            .ok_or("unsupported store source unexpectedly opened")?;
        assert!(error.to_string().contains("require Unix"), "{error}");
        assert!(!database.exists());
    }

    Ok(())
}
