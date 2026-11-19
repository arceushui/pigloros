#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Public ADR-123 §3a vectors for the Gateway store installation command
//! (Redmine #1467): it runs only under the exclusive sibling mode lock.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    use piglor_gateway::mode_profile::{GatewayModeErrorV1, GatewayModeStoreLockV1};
    use piglor_gateway::store_installation::{
        install_gateway_store_v1, GatewayStoreInstallationErrorV1, OwnerStoreInstallationV1,
    };
    use pos_store::sqlite::SqliteStore;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const NAMESPACE: &str = ".pigloros-store-namespace-v1";

    /// A private directory with an ordinary `SqliteStore` main file in WAL
    /// mode, closed, with the private file modes installation requires.
    struct Store {
        directory: tempfile::TempDir,
    }

    impl Store {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let store = Self { directory };
            drop(SqliteStore::open(&store.path())?);
            for name in ["main.db", "main.db-wal", "main.db-shm"] {
                let path = store.directory.path().join(name);
                if path.exists() {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(store)
        }

        fn path(&self) -> String {
            self.directory
                .path()
                .join("main.db")
                .to_string_lossy()
                .into_owned()
        }

        fn child(&self) -> PathBuf {
            self.directory.path().join(NAMESPACE)
        }
    }

    fn lock_refused(result: &Result<OwnerStoreInstallationV1, GatewayStoreInstallationErrorV1>) {
        assert!(matches!(
            result,
            Err(GatewayStoreInstallationErrorV1::ModeLock(
                GatewayModeErrorV1::StoreLockUnavailable
            ))
        ));
    }

    fn store_refused(result: Result<OwnerStoreInstallationV1, GatewayStoreInstallationErrorV1>) {
        let Err(GatewayStoreInstallationErrorV1::Store(error)) = result else {
            std::panic::resume_unwind(Box::new("expected the store installation refusal"));
        };
        assert_eq!(
            error.to_string(),
            "storage error: protected store installation unavailable"
        );
    }

    #[test]
    fn a_store_is_installed_once_and_the_sibling_lock_is_released() -> TestResult {
        let store = Store::new()?;
        assert_eq!(
            install_gateway_store_v1(&store.path())?,
            OwnerStoreInstallationV1::Installed
        );
        assert!(store.child().is_dir());
        assert_eq!(fs::read_dir(store.child())?.count(), 3);
        drop(GatewayModeStoreLockV1::exclusive(&store.path())?);
        assert_eq!(
            install_gateway_store_v1(&store.path())?,
            OwnerStoreInstallationV1::AlreadyInstalled
        );
        drop(GatewayModeStoreLockV1::exclusive(&store.path())?);
        Ok(())
    }

    #[test]
    fn a_held_sibling_lock_refuses_installation_before_the_child() -> TestResult {
        let store = Store::new()?;
        let serving = GatewayModeStoreLockV1::shared(&store.path())?;
        lock_refused(&install_gateway_store_v1(&store.path()));
        drop(serving);
        let migrating = GatewayModeStoreLockV1::exclusive(&store.path())?;
        lock_refused(&install_gateway_store_v1(&store.path()));
        drop(migrating);
        assert!(!store.child().exists());
        assert_eq!(
            install_gateway_store_v1(&store.path())?,
            OwnerStoreInstallationV1::Installed
        );
        Ok(())
    }

    #[test]
    fn a_store_refusal_leaves_no_child_and_releases_the_lock() -> TestResult {
        let store = Store::new()?;
        let main = store.directory.path().join("main.db");
        fs::set_permissions(&main, fs::Permissions::from_mode(0o640))?;
        store_refused(install_gateway_store_v1(&store.path()));
        assert!(!store.child().exists());
        drop(GatewayModeStoreLockV1::exclusive(&store.path())?);

        // A symlinked main path shares the store's sibling lock, but the
        // installation does not follow it.
        fs::set_permissions(&main, fs::Permissions::from_mode(0o600))?;
        let alias = store.directory.path().join("alias.db");
        symlink(&main, &alias)?;
        store_refused(install_gateway_store_v1(&alias.to_string_lossy()));
        assert!(!store.child().exists());

        // A directory path names no store, so it has no sibling lock.
        lock_refused(&install_gateway_store_v1(&format!(
            "{}/",
            store.directory.path().to_string_lossy()
        )));
        assert!(!store.child().exists());
        Ok(())
    }

    #[test]
    fn an_ordinary_open_of_an_installed_store_is_refused_under_the_sibling_lock() -> TestResult {
        let store = Store::new()?;
        assert_eq!(
            install_gateway_store_v1(&store.path())?,
            OwnerStoreInstallationV1::Installed
        );
        let serving = GatewayModeStoreLockV1::shared(&store.path())?;
        let Err(error) = SqliteStore::open(&store.path()) else {
            std::panic::resume_unwind(Box::new("expected the ordinary open refusal"));
        };
        assert!(error.to_string().contains("protected namespace"));
        drop(serving);
        Ok(())
    }
}
