#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Public ADR-123 §3a quiescent installation vectors; no native binding is created.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use pos_core::CoreError;
    use pos_store::owner_store_installation::{
        install_owner_store_namespace_v1, OwnerStoreInstallationV1,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const NAMESPACE: &str = ".pigloros-store-namespace-v1";
    const MAIN: &str = "main.db";
    /// A `SQLite` 3 header in WAL mode: file format write and read versions 2.
    const WAL_HEADER: [u8; 20] = *b"SQLite format 3\0\x10\x00\x02\x02";

    struct Fixture {
        directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Self::with_main(&WAL_HEADER)
        }

        fn with_main(contents: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            create(directory.path(), MAIN, contents)?;
            Ok(Self { directory })
        }

        fn path(&self) -> &Path {
            self.directory.path()
        }

        fn child(&self) -> PathBuf {
            self.path().join(NAMESPACE)
        }

        /// The §3b reserved entries keyed on the main file.
        fn entries(&self) -> Result<[PathBuf; 3], Box<dyn std::error::Error>> {
            let metadata = fs::metadata(self.path().join(MAIN))?;
            let child = self.child();
            Ok(
                ["store-namespace", "gateway-consent-lease", "gateway-mode"].map(|entry| {
                    child.join(format!(
                        "{entry}.v1.{:016x}.{:016x}.lock",
                        metadata.dev(),
                        metadata.ino()
                    ))
                }),
            )
        }

        fn install(&self) -> Result<OwnerStoreInstallationV1, CoreError> {
            install_owner_store_namespace_v1(self.path(), MAIN)
        }

        fn make_child(&self) -> TestResult {
            fs::create_dir(self.child())?;
            fs::set_permissions(self.child(), fs::Permissions::from_mode(0o700))?;
            Ok(())
        }

        fn assert_installed(&self) -> TestResult {
            let child = fs::symlink_metadata(self.child())?;
            assert!(child.is_dir());
            assert_eq!(child.mode() & 0o7777, 0o700);
            assert_eq!(fs::read_dir(self.child())?.count(), 3);
            for entry in self.entries()? {
                let metadata = fs::symlink_metadata(entry)?;
                assert!(metadata.is_file());
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(metadata.len(), 0);
            }
            assert_eq!(fs::read(self.path().join(MAIN))?, WAL_HEADER);
            Ok(())
        }
    }

    fn create(directory: &Path, name: &str, contents: &[u8]) -> TestResult {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))?
            .write_all(contents)?;
        Ok(())
    }

    fn refused(result: Result<OwnerStoreInstallationV1, CoreError>) {
        let Err(error) = result else {
            std::panic::resume_unwind(Box::new("expected installation refusal"));
        };
        assert_eq!(
            error.to_string(),
            CoreError::Storage("protected store installation unavailable".to_owned()).to_string()
        );
    }

    #[test]
    fn a_fresh_store_is_installed_once() -> TestResult {
        let fixture = Fixture::new()?;
        assert_eq!(fixture.install()?, OwnerStoreInstallationV1::Installed);
        fixture.assert_installed()?;
        assert_eq!(
            fixture.install()?,
            OwnerStoreInstallationV1::AlreadyInstalled
        );
        fixture.assert_installed()?;
        assert_eq!(fs::read_dir(fixture.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn a_rerun_completes_an_interrupted_installation() -> TestResult {
        // Each prefix of the reserved entries models a run interrupted after
        // creating the child and that many entries.
        for existing in 0..3 {
            let fixture = Fixture::new()?;
            fixture.make_child()?;
            for entry in &fixture.entries()?[..existing] {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(entry)?;
            }
            assert_eq!(fixture.install()?, OwnerStoreInstallationV1::Installed);
            fixture.assert_installed()?;
        }
        Ok(())
    }

    #[test]
    fn an_unsafe_existing_child_is_refused_without_repair() -> TestResult {
        let fixture = Fixture::new()?;
        fixture.make_child()?;
        fs::set_permissions(fixture.child(), fs::Permissions::from_mode(0o750))?;
        refused(fixture.install());
        assert_eq!(
            fs::metadata(fixture.child())?.permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(fs::read_dir(fixture.child())?.count(), 0);

        let fixture = Fixture::new()?;
        let elsewhere = tempfile::tempdir()?;
        fs::set_permissions(elsewhere.path(), fs::Permissions::from_mode(0o700))?;
        symlink(elsewhere.path(), fixture.child())?;
        refused(fixture.install());
        assert_eq!(fs::read_dir(elsewhere.path())?.count(), 0);

        let fixture = Fixture::new()?;
        create(fixture.path(), NAMESPACE, b"not a directory")?;
        refused(fixture.install());
        assert_eq!(fs::read(fixture.child())?, b"not a directory");
        Ok(())
    }

    #[test]
    fn an_unsafe_existing_entry_is_refused_without_repair() -> TestResult {
        for kind in ["mode", "symlink", "directory", "hardlink"] {
            let fixture = Fixture::new()?;
            fixture.make_child()?;
            let [first, second, _] = fixture.entries()?;
            match kind {
                "mode" => {
                    create(&fixture.child(), "kept", b"kept")?;
                    fs::rename(fixture.child().join("kept"), &second)?;
                    fs::set_permissions(&second, fs::Permissions::from_mode(0o640))?;
                }
                "symlink" => symlink(fixture.path().join(MAIN), &second)?,
                "directory" => fs::create_dir(&second)?,
                _ => {
                    create(&fixture.child(), "kept", b"kept")?;
                    fs::rename(fixture.child().join("kept"), &second)?;
                    fs::hard_link(&second, fixture.child().join("alias"))?;
                }
            }
            refused(fixture.install());
            // The entry before it was created; the unsafe one is unchanged.
            assert!(first.is_file());
            let metadata = fs::symlink_metadata(&second)?;
            match kind {
                "mode" => {
                    assert_eq!(metadata.mode() & 0o7777, 0o640);
                    assert_eq!(fs::read(&second)?, b"kept");
                }
                "symlink" => assert!(metadata.file_type().is_symlink()),
                "directory" => assert!(metadata.is_dir()),
                _ => assert_eq!(metadata.nlink(), 2),
            }
            assert_eq!(fs::read(fixture.path().join(MAIN))?, WAL_HEADER);
        }
        Ok(())
    }

    #[test]
    fn a_main_file_that_is_not_a_wal_database_is_refused_before_the_child() -> TestResult {
        let mut rollback = WAL_HEADER;
        rollback[18] = 1;
        rollback[19] = 1;
        for contents in [
            &rollback[..],
            b"unchanged file contents",
            &WAL_HEADER[..19],
            b"",
        ] {
            let fixture = Fixture::with_main(contents)?;
            refused(fixture.install());
            assert!(!fixture.child().exists());
            assert_eq!(fs::read(fixture.path().join(MAIN))?, contents);
        }
        Ok(())
    }

    #[test]
    fn unsafe_directories_main_files_and_companions_are_refused_before_the_child() -> TestResult {
        let fixture = Fixture::new()?;
        refused(install_owner_store_namespace_v1(
            &fixture.path().join("missing"),
            MAIN,
        ));
        for name in [
            "missing",
            "",
            "..",
            "sub/main.db",
            "file:main.db",
            NAMESPACE,
        ] {
            refused(install_owner_store_namespace_v1(fixture.path(), name));
        }
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o750))?;
        refused(fixture.install());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(fixture.path().join(MAIN), fs::Permissions::from_mode(0o640))?;
        refused(fixture.install());
        assert!(!fixture.child().exists());

        let working_directory = std::env::current_dir()?;
        let directory = tempfile::tempdir_in(&working_directory)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        create(directory.path(), MAIN, &WAL_HEADER)?;
        refused(install_owner_store_namespace_v1(
            directory.path().strip_prefix(&working_directory)?,
            MAIN,
        ));
        assert!(!directory.path().join(NAMESPACE).exists());

        for (suffix, mode) in [("-journal", 0o600), ("-wal", 0o640), ("-shm", 0o640)] {
            let fixture = Fixture::new()?;
            let name = format!("{MAIN}{suffix}");
            create(fixture.path(), &name, b"unchanged file contents")?;
            fs::set_permissions(fixture.path().join(&name), fs::Permissions::from_mode(mode))?;
            refused(fixture.install());
            assert!(!fixture.child().exists());
            assert_eq!(
                fs::read(fixture.path().join(name))?,
                b"unchanged file contents"
            );
        }
        Ok(())
    }

    #[test]
    fn a_real_sqlite_database_installs_only_in_wal_mode() -> TestResult {
        for (journal_mode, installed) in [("WAL", true), ("DELETE", false)] {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let main = directory.path().join(MAIN);
            let connection = rusqlite::Connection::open(&main)?;
            let mode: String = connection.query_row(
                &format!("PRAGMA journal_mode = {journal_mode}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(mode.to_ascii_uppercase(), journal_mode);
            connection.execute_batch("CREATE TABLE fixture (id INTEGER PRIMARY KEY)")?;
            connection.close().map_err(|(_, error)| error)?;
            fs::set_permissions(&main, fs::Permissions::from_mode(0o600))?;
            let result = install_owner_store_namespace_v1(directory.path(), MAIN);
            if installed {
                assert_eq!(result?, OwnerStoreInstallationV1::Installed);
            } else {
                refused(result);
                assert!(!directory.path().join(NAMESPACE).exists());
            }
        }
        Ok(())
    }
}
