#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]
#![forbid(unsafe_code)]

use std::fs::File;
use std::os::windows::fs::MetadataExt;

use pos_owner_bridge::{BridgeError, UnavailableCode};

/// Observe candidate Windows `[volume_serial, file_index]` metadata.
///
/// This is a handle snapshot, not a store binding or encryption authority.
/// The caller must separately establish the connection-owned `SQLite` main-file
/// handle, its lifetime, and the remaining ADR-097/ADR-132 activation gates.
/// Hard-link aliases of the same file intentionally yield the same identity.
///
/// # Errors
/// Refuses non-regular or reparse files, a non-private owner/DACL, non-NTFS
/// handles, mismatched volume observations or any metadata failure.
pub fn store_file_id(file: &File) -> Result<[u64; 2], BridgeError> {
    candidate(file).map_err(|()| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
}

fn candidate(file: &File) -> Result<[u64; 2], ()> {
    file.metadata()
        .ok()
        .ok_or(())
        .and_then(|metadata| {
            (metadata.is_file() && metadata.file_attributes() & 0x400 == 0)
                .then_some(())
                .ok_or(())
        })
        .and_then(|()| crate::Native::require_private_file(file))
        .and_then(|()| crate::Native::cleanup_file_volume(file))
        .and_then(|volume| {
            crate::Native::file_identity(file).and_then(|(observed_volume, index)| {
                (observed_volume == volume)
                    .then_some([u64::from(volume), index])
                    .ok_or(())
            })
        })
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn exercise_store_file_identity() {
        use std::fs::{self, OpenOptions};
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::PathBuf;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};
        use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        use crate::adapter::native_tests::pass;

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _removed = fs::remove_dir_all(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "piglor-store-id-{}-{}",
            std::process::id(),
            pass(SystemTime::now().duration_since(UNIX_EPOCH)).as_nanos()
        ));
        pass(fs::create_dir(&path));
        let fixture = Fixture(path);
        let private = fixture.0.join("private");
        pass(crate::create_private_directory(&private));
        Self::exercise_default_owner_refusal(&private);
        let original = private.join("store.db");
        let file = pass(Self::create_private_ledger_file(&original));
        pass(Self::diagnose_private_file(&file));
        pass(Self::cleanup_file_volume(&file));
        pass(Self::file_identity(&file));
        let identity = pass(store_file_id(&file));
        assert_eq!(pass(store_file_id(&pass(file.try_clone()))), identity);
        let alias = private.join("alias.db");
        pass(fs::hard_link(&original, &alias));
        assert_eq!(pass(store_file_id(&pass(File::open(&alias)))), identity);
        let copied = private.join("copy.db");
        let copied_file = pass(Self::create_private_ledger_file(&copied));
        drop(copied_file);
        pass(fs::write(&copied, pass(fs::read(&original))));
        assert_ne!(pass(store_file_id(&pass(File::open(&copied)))), identity);
        let moved = private.join("moved.db");
        pass(fs::rename(&original, &moved));
        let replacement = pass(Self::create_private_ledger_file(&original));
        assert_eq!(pass(store_file_id(&file)), identity);
        assert_ne!(pass(store_file_id(&replacement)), identity);
        let directory = pass(
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
                .open(&private),
        );
        assert_eq!(
            store_file_id(&directory),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(directory);
        let device = pass(File::open("NUL"));
        assert_eq!(
            store_file_id(&device),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(device);
        let result = pass(
            Command::new("icacls.exe")
                .arg(&moved)
                .args(["/grant", "*S-1-1-0:(R)"])
                .output(),
        );
        assert!(result.status.success());
        assert_eq!(
            store_file_id(&file),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(replacement);
        drop(file);
    }

    /// A default-created file is refused wherever the host's token default
    /// owner differs from the process user.
    ///
    /// A host without that mismatch reports the case as unqualified instead
    /// of claiming the refusal.
    fn exercise_default_owner_refusal(private: &std::path::Path) {
        use std::io::Write as _;

        use crate::adapter::native_tests::pass;

        let path = private.join("default-owner-fixture.db");
        let file = pass(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path),
        );
        let wrong_owner = Self::diagnose_private_file(&file)
            .err()
            .is_some_and(|detail| {
                let owner = |label: &str| {
                    pass(
                        detail
                            .split_once(label)
                            .and_then(|(_, tail)| tail.split_once("D:"))
                            .ok_or("default fixture owner observation failed"),
                    )
                    .0
                };
                owner("actual=O:") != owner("expected=[\"O:")
            });
        assert!(!wrong_owner || store_file_id(&file).is_err());
        pass(writeln!(
            std::io::stderr(),
            "SNL1_WRONG_OWNER_CASE={}",
            ["unqualified", "qualified"][usize::from(wrong_owner)]
        ));
        drop(file);
        pass(std::fs::remove_file(path));
    }
}
